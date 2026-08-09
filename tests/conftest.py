def pytest_addoption(parser):
    parser.addoption("--fast", action="store_true",
                     help="Skip private testdata")
    parser.addoption("--limit", action="store", default=None, metavar="DIR",
                     help="Limit test cases to specific directory")
