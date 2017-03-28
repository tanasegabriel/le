from logentries.config import *

def test_load_configured_logs(capsys):
    config = Config()
    
    conf = ConfigParser.SafeConfigParser({
        USER_KEY_PARAM: '',
        AGENT_KEY_PARAM: '',
        API_KEY_PARAM: '',
        FILTERS_PARAM: '',
        FORMATTERS_PARAM: '',
        FORMATTER_PARAM: '',
        ENTRY_IDENTIFIER_PARAM: '',
        SUPPRESS_SSL_PARAM: '',
        FORCE_DOMAIN_PARAM: '',
        USE_CA_PROVIDED_PARAM: '',
        DATAHUB_PARAM: '',
        SYSSTAT_TOKEN_PARAM: '',
        STATE_FILE_PARAM: '',
        HOSTNAME_PARAM: '',
        PULL_SERVER_SIDE_CONFIG_PARAM: 'True',
        INCLUDE_PARAM: '',
        PROXY_TYPE_PARAM: '',
        PROXY_URL_PARAM: '',
        PROXY_PORT_PARAM: '',
    })
    conf.add_section("configured log")
    conf.set("configured log", PATH_PARAM,"/some/path")

    config._load_configured_logs(conf)
    
    logs = config.configured_logs
    
    assert len(logs) is 1
    assert logs[0].name is "configured log"
    assert logs[0].path is "/some/path"
    
    
    

