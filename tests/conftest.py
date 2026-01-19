def pytest_addoption(parser):
    parser.addoption("--fast", action="store_true",
                     help="Skip private testdata")
