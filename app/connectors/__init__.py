def connector_registry():
    from app.connectors.registry import connector_registry as _connector_registry

    return _connector_registry()


def connector_map():
    from app.connectors.registry import connector_map as _connector_map

    return _connector_map()


__all__ = ["connector_registry", "connector_map"]
