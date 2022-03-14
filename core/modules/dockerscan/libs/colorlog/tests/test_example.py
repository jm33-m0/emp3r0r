def test_example():
    """Tests the usage example from the README"""
    import colorlog

    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(levelname)s:%(name)s:%(message)s'))
    logger = colorlog.getLogger('example')
    logger.addHandler(handler)
