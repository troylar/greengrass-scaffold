import mock
from mock import patch
from sod import GreengrassDevice


def os_path_join_mock(path, *paths):
    j_path = [path]
    for p in paths:
        j_path.append(p)
    return '/'.join(j_path)


@patch('os.path.join')
def test_can_set_greengrass_thingid(join_mock):
    join_mock.side_effect = os_path_join_mock
    device_name = 'this_device'
    p = GreengrassDevice(DeviceName=device_name)
    assert p.device_name == device_name


@patch('os.path.join')
def test_can_set_greengrass_private_key_path(join_mock):
    join_mock.side_effect = os_path_join_mock
    private_key_path = 'here'
    p = GreengrassDevice(DeviceName='test',
                         PrivateKeyPath=private_key_path)
    assert p.private_key_path == private_key_path


@patch('os.path.join')
def test_can_set_greengrass_certificate_path(join_mock):
    join_mock.side_effect = os_path_join_mock
    certificate_path = 'here'
    p = GreengrassDevice(CertPath=certificate_path,
                         DeviceName='test')
    assert p.cert_path == certificate_path


@patch('os.path.join')
def test_ca_root_full_path_is_set(join_mock):
    join_mock.side_effect = os_path_join_mock
    p = GreengrassDevice(DeviceName='my_device',
                         group_path='./folder',
                         CaName='root.crt')
    assert p.root_ca_path == './devices/credentials/my_device/root.crt'


@mock.patch('sod.GreengrassDevice.does_root_cert_exist')
@mock.patch('sod.GreengrassDevice.discover_ggc')
@patch('os.path.join')
def test_no_root_cert_causes_discovery(join_mock, mock_discover_ggc, mock_does_root_cert_exist):  # noqa: E501
    join_mock.side_effect = os_path_join_mock
    p = GreengrassDevice(DeviceName='my_device',
                         CaName='root.crt')
    mock_does_root_cert_exist.return_value = False
    p.check_root_cert()
    mock_discover_ggc.assert_called_with()


@mock.patch('sod.GreengrassDevice.does_root_cert_exist')
@mock.patch('sod.GreengrassDevice.discover_ggc')
@patch('os.path.join')
@mock.patch('sod.GreengrassDevice.get_ggc_addr')
def test_existing_root_cert_causes_no_discovery(get_ggc_addr_mock,
                                                join_mock,
                                                mock_discover_ggc,
                                                mock_does_root_cert_exist):
    join_mock.side_effect = os_path_join_mock
    get_ggc_addr_mock.return_value = '127.0.0.1'
    p = GreengrassDevice(DeviceName='my_device',
                         CaName='root.crt')
    mock_does_root_cert_exist.return_value = True
    p.check_root_cert()
    assert not mock_discover_ggc.called
