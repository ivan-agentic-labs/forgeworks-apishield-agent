"""Offline bounded contract parsing shared by artifact validation and analysis."""
import yaml
import math
import os
import stat

MAX_CONTRACT_BYTES = 2 * 1024 * 1024


def read_contract(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise ValueError('CONTRACT_INPUT_NOT_REGULAR_FILE')
            return file.read(MAX_CONTRACT_BYTES + 1)
    except OSError as error:
        raise ValueError('CONTRACT_INPUT_UNAVAILABLE') from error


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, int)) or isinstance(key, bool) or key in result:
            raise ValueError('CONTRACT_DUPLICATE_OR_INVALID_KEY')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def load_contract(body):
    if len(body) > MAX_CONTRACT_BYTES:
        raise ValueError('CONTRACT_TOO_LARGE')
    try:
        if any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(body)):
            raise ValueError('CONTRACT_ALIASES_UNSUPPORTED')
        document = yaml.load(body, Loader=UniqueLoader)
        if not isinstance(document, dict) or not isinstance(document.get('paths'), dict):
            raise ValueError('CONTRACT_INPUT_INVALID')
        # A malformed path must never silently disappear from the impact diff.
        # OpenAPI path-item keys are absolute /-prefixed strings.
        for route, item in document['paths'].items():
            if not isinstance(route, str) or not route.startswith('/') or not isinstance(item, dict):
                raise ValueError('CONTRACT_PATH_INVALID')
        pending = [(document, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if count > 20000 or depth > 64:
                raise ValueError('CONTRACT_STRUCTURE_LIMIT')
            if isinstance(value, dict):
                for keyword in ('$ref', '$dynamicRef'):
                    if keyword in value and (not isinstance(value[keyword], str) or not value[keyword].startswith('#/')):
                        raise ValueError('CONTRACT_EXTERNAL_REFERENCE_DISABLED')
                pending.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
            elif isinstance(value, float) and not math.isfinite(value):
                raise ValueError('CONTRACT_NONFINITE_NUMBER')
        return document
    except (yaml.YAMLError, UnicodeError, RecursionError, TypeError) as error:
        raise ValueError('CONTRACT_INPUT_INVALID') from error


def unsupported_constructs(document):
    """Never silently treat unresolved references/composition as fully covered."""
    pending = [(document, '')]
    while pending:
        value, pointer = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                part = str(key).replace('~', '~0').replace('/', '~1')
                child = pointer + '/' + part
                if key in {'$ref', '$dynamicRef', 'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else'}:
                    yield child
                pending.append((item, child))
        elif isinstance(value, list):
            pending.extend((item, pointer + '/' + str(index)) for index, item in enumerate(value))
