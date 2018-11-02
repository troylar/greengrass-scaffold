from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTShadowClient
import json
import sys
import logging
import os
import re
import boto3

from AWSIoTPythonSDK.core.greengrass.discovery.providers import DiscoveryInfoProvider  # noqa: E501
from AWSIoTPythonSDK.core.protocol.connection.cores import ProgressiveBackOffCore  # noqa: E501
from AWSIoTPythonSDK.exception.AWSIoTExceptions import DiscoveryInvalidRequestException  # noqa: E501


class SodPlug(object):

    def __init__(self, **kwargs):
        self.device_name = kwargs.get('DeviceName')
        print('Device name: {}'.format(self.device_name))
        self.device_root = kwargs.get('DeviceRoot', './devices')
        self.device_path = kwargs.get('DevicePath',
                                      os.path.join(self.device_root,
                                                   'credentials',
                                                   self.device_name))
        self.iot_ca_path = kwargs.get('IotCaPath', './root/root-cert.pem')
        self.cert_path = kwargs.get('CertPath',
                                    os.path.join(self.device_path,
                                                 'cert.pem'))
        self.private_key_path = kwargs.get('PrivateKeyPath',
                                           os.path.join(self.device_path,
                                                        'private.key'))
        self.iot_endpoint = kwargs.get('IotEndPoint')
        self.ca_name = kwargs.get('CaName', 'root-ca.cert')
        self.shadow_thing_name = kwargs.get('ThingName', self.device_name)
        self.max_discovery_retries = int(kwargs.get('MaxDiscoveryRetries', '10'))  # noqa: E501
        self.ggc_addr_name = kwargs.get('CoreName', 'ggc-core')
        self.root_ca_path = os.path.join(self.device_path, self.ca_name)
        print('iot_endpoint: {}'.format(self.iot_endpoint))
        print('shadow_thing_name: {}'.format(self.shadow_thing_name))
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.logger = logging.getLogger('AWSIoTPythonSDK.core')
        self.logger.setLevel(logging.ERROR)
        streamHandler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')  # noqa: E501
        streamHandler.setFormatter(formatter)
        self.logger.addHandler(streamHandler)
        self.gg = boto3.client('greengrass')
        self.iot_client = boto3.client('iot')
        self.iot_data = boto3.client('iot-data')
        self.publish_only = kwargs.get('PublishOnly', False)
        self.custom_shadow_callback = kwargs.get('CustomShadowCallback', self.customShadowCallback_Update)
        self.delta_callback = kwargs.get('DeltaCallback', self.delta_callback)
        print(self.custom_shadow_callback)
        self.get_thing()

    def get_thing(self):
        response = self.iot_client.describe_thing(thingName=self.shadow_thing_name)
        self.thing_arn = response['thingArn']
        print(self.thing_arn)

    def get_shadow(self):
        response = self.iot_data.get_thing_shadow(thingName=self.shadow_thing_name)
        shadowData = json.loads(response["payload"].read().decode("utf-8"))
        return(shadowData)

    def update_shadow(self, **kwargs):
        desired = kwargs.get('Desired')
        reported = kwargs.get('Reported')
        doc = {}
        doc['state'] = {}
        if desired:
            doc['state']['desired'] = desired
        if reported:
            doc['state']['reported'] = reported
        json_payload = json.dumps(doc)
        print('Updating shadow: {}'.format(json_payload))
        print(self.custom_shadow_callback)
        self.device_shadow_handler.shadowUpdate(json_payload,
                                                self.custom_shadow_callback, # noqa E:501
                                                10)

    def does_root_cert_exist(self):
        return os.path.isfile(self.root_ca_path)

    def check_root_cert(self):
        if not self.does_root_cert_exist():
            self.discover_ggc()
        else:
            self.get_ggc_addr()
            print('Greengrass core has already been discovered.')

    def configure_mqtt_client(self):
        self.mqtt_client = self.mqtt_shadow_client.getMQTTConnection()
        self.mqtt_client.configureAutoReconnectBackoffTime(1, 32, 20)
        self.mqtt_client.configureOfflinePublishQueueing(-1)
        self.mqtt_client.configureDrainingFrequency(2)  # Draining: 2 Hz
        self.mqtt_client.configureConnectDisconnectTimeout(10)  # 10 sec
        self.mqtt_client.configureMQTTOperationTimeout(5)  # 5 sec

    def configure_shadow_client(self):
        self.mqtt_shadow_client = AWSIoTMQTTShadowClient(self.device_name)
        print('Created shadow client for {}'.format(self.device_name))
        self.mqtt_shadow_client.configureEndpoint(self.ggc_host_addr, 8883)  # noqa: E501
        self.mqtt_shadow_client.configureCredentials(
            self.root_ca_path, self.private_key_path, self.cert_path)

        # AWSIoTMQTTShadowClient configuration
        self.mqtt_shadow_client.configureAutoReconnectBackoffTime(1, 32, 20)  # noqa: E501
        self.mqtt_shadow_client.configureConnectDisconnectTimeout(10)
        self.mqtt_shadow_client.configureMQTTOperationTimeout(5)
        self.mqtt_shadow_client.connect()

    def delta_callback(self, payload, responseStatus, token):
        print('delta received')
        pass

    def register_handlers(self):
        self.device_shadow_handler = self.mqtt_shadow_client.createShadowHandlerWithName(self.shadow_thing_name, True)  # noqa: E501
        print('Registered shadow handlers for {}'.format(self.shadow_thing_name))  # noqa: E501
        if self.publish_only:
            return
        self.device_shadow_handler.shadowRegisterDeltaCallback(self.delta_callback)  # noqa: E501
        print('Registered delta callback for {}'.format(self.shadow_thing_name))  # noqa: E501

    def on_registered(self):
        pass

    def register(self, **kwargs):
        self.check_root_cert()
        self.configure_shadow_client()
        self.configure_mqtt_client()
        self.register_handlers()
        self.on_registered()

    def isIpAddress(self, value):
        match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}', value)
        if match:
            return True
        return False

    def get_ggc_addr(self):
        ggcHostPath = os.path.join(self.device_path, self.ggc_addr_name)
        f = open(ggcHostPath, 'r')
        self.ggc_host_addr = f.readline()
        print('Greengrass core: {}'.format(self.ggc_host_addr))

    def discover_ggc(self):
        backOffCore = ProgressiveBackOffCore()
        discoveryInfoProvider = DiscoveryInfoProvider()
        discoveryInfoProvider.configureEndpoint(self.iot_endpoint)
        discoveryInfoProvider.configureCredentials(self.iot_ca_path,
                                                   self.cert_path,
                                                   self.private_key_path)
        print('Endpoint: {}'.format(self.iot_endpoint))
        print('iot_ca_path: {}'.format(self.iot_ca_path))
        print('cert_path: {}'.format(self.cert_path))
        print('private_key_path: {}'.format(self.private_key_path))
        print('device_name: {}'.format(self.device_name))
        discoveryInfoProvider.configureTimeout(10)  # 10 sec
        retryCount = self.max_discovery_retries
        discovered = False
        groupCA = None
        coreInfo = None
        while retryCount != 0:
            try:
                discoveryInfo = discoveryInfoProvider.discover(self.device_name)  # noqa: E501
                caList = discoveryInfo.getAllCas()
                coreList = discoveryInfo.getAllCores()
                groupId, ca = caList[0]
                coreInfo = coreList[0]
                print('Discovered GGC: ' + coreInfo.coreThingArn +
                      ' from Group: ' + groupId)
                host_addr = ''

                for addr in coreInfo.connectivityInfoList:
                    host_addr = addr.host
                    if self.isIpAddress(host_addr):
                        break

                print('Discovered GGC Host Address: ' + host_addr)
                self.ggc_host_addr = host_addr
                print('Now we persist the connectivity/identity information')
                groupCA = os.path.join(self.device_path, self.ca_name)
                ggcHostPath = os.path.join(self.device_path,
                        self.ggc_addr_name)  # noqa: E501
                groupCAFile = open(groupCA, 'w')
                groupCAFile.write(ca)
                groupCAFile.close()
                groupHostFile = open(ggcHostPath, 'w')
                groupHostFile.write(host_addr)
                groupHostFile.close()

                discovered = True
                print('Now proceed to the connecting flow...')
                break
            except DiscoveryInvalidRequestException as e:
                print('Invalid discovery request detected!')
                print('Type: ' + str(type(e)))
                print('Error message: ' + e.message)
                print('Stopping...')
                break
            except BaseException as e:
                print('Error in discovery!')
                print('Type: ' + str(type(e)))
                print('Error message: ' + e.message)
                retryCount -= 1
                raise
                print('\n'+str(retryCount) + '/' +
                      str(self.max_discovery_retries) + ' retries left\n')
                print('Backing off...\n')
                backOffCore.backOff()

        if not discovered:
            print('Discovery failed after ' + str(self.max_discovery_retries)
                  + ' retries. Exiting...\n')
            sys.exit(-1)

    # Custom Shadow callback for updating the reported state in shadow
    def customShadowCallback_Update(self, payload, responseStatus, token):
        print(payload)
        if responseStatus == 'timeout':
            print('Update request ' + token + ' time out!')
        if responseStatus == 'accepted':
            print('~~~~~~~~~~ Shadow Update Accepted ~~~~~~~~~~~~~')
            print('Update request with token: ' + token + ' accepted!')
            print(payload)
            print('~~~~~~~~~~~~~~~~~~~~~~~\n\n')
        if responseStatus == 'rejected':
            print('Update request ' + token + ' rejected!')

    def publish(self, topic, message, qos_level=0):
        print('Publishing {} to {}'.format(message, topic))
        if (self.mqtt_client.publish(topic, json.dumps(message), qos_level)):
            print('PUBLISHED')
        else:
            print('NOT PUBLISHED')

    def update_device_shadow(self, device, message, qos_level=0):
        desired = {'state': {'desired': message}}
        topic = '$aws/things/{}/shadow/update'.format(device)
        print('Publishing {} to {}'.format(desired, topic))
        if (self.mqtt_client.publish(topic,
                                     json.dumps(desired),
                                     qos_level)):
            print('PUBLISHED')
        else:
            print('NOT PUBLISHED')
