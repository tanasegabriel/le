import json
import httpretty
from mock import Mock, PropertyMock, patch
from logentries import le
from logentries.constants import NOT_SET, LOGSET_URL
from logentries.metrics import MetricsConfig


create_logset_response = {
    "logset": {
        "description": "",
        "id": "abcd1234-abcd-0000-abcd-abcd1234",
        "logs_info": [],
        "name": "Test Logset",
        "user_data": {}
    }
}

@httpretty.activate
@patch('logentries.le.collect_log_names')
@patch('logging.Logger.info')
def test_register(logger, log_names):
    log_names.return_value = []
    le.CONFIG = mock_config_object()
    
    httpretty.register_uri(httpretty.POST, LOGSET_URL, status=201, content_type='application/json', body=json.dumps(create_logset_response))
    
    le.cmd_register([])

    logger.assert_called_with('Registered %s (%s)', 'name', 'Test Logset')


@patch('logging.Logger.warning')
@patch('logentries.le._is_followed', return_value=True)
def test_follow(is_followed, logger):
    le.CONFIG = mock_config_object()

    le.cmd_follow(['/example.log'])

    logger.assert_called_with('Already following %s', '/example.log')
    
    
@patch('logentries.le.start_followers')
@patch('logentries.utils.default_cert_file')
@patch('logentries.le.DefaultTransport.get')
@patch('logentries.le._load_state')
@patch('logentries.le.save_state')
@patch('logentries.le.TerminationNotifier.terminate')
def test_monitor_starts_followers(terminate, save_state, load_state, default_transport, default_cert_file, start_followers, capsys):
    le.CONFIG = mock_config_object()
    default_cert_file.return_value = ''
    default_transport.return_value = ''
    load_state.return_value = {}
    save_state.return_value = ''
    terminate.return_value = True
    followers = [Mock()]
    start_followers.return_value = (followers, default_transport, start_followers)

    le.cmd_monitor([])
    
    out, err = capsys.readouterr()
        
    start_followers.assert_called_once()
    assert "Shutting down" in err
    

def mock_config_object():
    config_attributes = {'load.return_value': True}
    mock_config = Mock(force=False,
                       debug_events=True,
                       daemon=False,
                       config_dir_name='',
                       hostname='Test Logset',
                       api_key='123456789012345678901234567890123456',
                       agent_key=NOT_SET,
                       metrics=MetricsConfig(),
                       debug_stats_only=False,
                       **config_attributes)
    type(mock_config).name = PropertyMock(return_value='name')
    return mock_config

