import httpretty
import json

from mock import Mock, PropertyMock
from logentries import le
from logentries.constants import LOGSET_URL, NOT_SET
from logentries.metrics import MetricsConfig


get_logset_response = {
  "logsets": [
    {
      "id": "33c5806c-1234-1234-1234-be9fc0f7d0f4",
      "name": "Logset1",
      "user_data": {
        "le_agent_distribution": "macOS",
        "le_agent_distver": "1.2.3",
        "le_agent_filename": "test"},
      "logs_info": [
        {
          "id": "d42eaaaf-1234-1234-1234-6559443df876",
          "name": "SyslogD Log",
          "links": [
            {
              "rel": "Self",
              "href": "https://rest.logentries.com/management/logs/d42eaaaf-1234-1234-1234-6559443df876"
            }
          ]
        }         
      ]
    },
    {
      "id": "33c5806c-1234-1234-1234-be9fc0f7d0f4",
      "name": "Logset2",
      "user_data": {},
      "logs_info": [
        {
          "id": "d42eaaaf-1234-1234-1234-6559443df876",
          "name": "SyslogD Log",
          "links": [
            {
              "rel": "Self",
              "href": "https://rest.logentries.com/management/logs/d42eaaaf-1234-1234-1234-6559443df876"
            }
          ]
        }         
      ]
    }
  ]
}
        
def test_list_basic_components(capsys):
    
    le.cmd_ls([])
    
    out, err = capsys.readouterr()
    
    assert "apps" in out
    assert "clusters" in out
    assert "hostnames" in out
    assert "hosts" in out
    assert "logs" in out
    assert "logtypes" in out
    assert "6 items" in err
    

@httpretty.activate
def test_list_hosts(capsys):
    le.CONFIG = mock_config_object()

    httpretty.register_uri(httpretty.GET, LOGSET_URL, status=200, content_type='application/json', body=json.dumps(get_logset_response))

    le.cmd_ls(['hosts'])
    
    out, err = capsys.readouterr()
    
    assert "Logset1" in out
    assert "Logset2" in out
    assert "2 hosts" in err


@httpretty.activate
def test_list_single_host(capsys):
    le.CONFIG = mock_config_object()

    httpretty.register_uri(httpretty.GET, LOGSET_URL, status=200, content_type='application/json',
                           body=json.dumps(get_logset_response))

    le.cmd_ls(['hosts/Logset1'])

    out, err = capsys.readouterr()

    assert "name = Logset1" in out
    assert "key = 33c5806c-1234-1234-1234-be9fc0f7d0f4" in out
    assert "distribution = macOS" in out
    assert "distver = 1.2.3" in out
    assert "name = test" in out
    
@httpretty.activate
def test_list_logs_for_host(capsys):
    le.CONFIG = mock_config_object()

    httpretty.register_uri(httpretty.GET, LOGSET_URL, status=200, content_type='application/json',
                           body=json.dumps(get_logset_response))

    le.cmd_ls(['hosts/Logset1/'])

    out, err = capsys.readouterr()

    assert "SyslogD Log" in out
    assert "1 log" in err


def mock_config_object():
    config_attributes = {'load.return_value': True,
                         'api_key_required.return_value': True}
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

