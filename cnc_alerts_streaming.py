import requests
import yaml
import logging
import json
import configparser
import ast

# Create a logger
logger = logging.getLogger(__name__)

# Set the logging level
logger.setLevel(logging.INFO)

# Create a file handler
file_handler = logging.FileHandler('cnc_alerts.log')

# Set the file handler's format
file_handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))

# Add the file handler to the logger
logger.addHandler(file_handler)


# dcloud setup
CONFIG_FILE_PATH = "/Users/mfarook2/Desktop/CROSSWORK/CNC5.0/Enable_kpi_profiles/AUTO_ENABLE_NETWORK_PROFILES/config.yaml"

Ticket_Token_Header = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': "text/plain",
    'Cache-Control': "no-cache",
}

Ticket_Token_Header_JSON = {
    'Content-Type': 'application/json',
    'Accept': "text/plain",
    'Cache-Control': "no-cache",
}

serviceNowURL = 'https://<instanceID>.service-now.com/api/now/table/incident'
authorization = '<Authorization token>'

def create_servicenow_ticket(alert):
    """
    Create a ServiceNow ticket based on the provided alert information.

    Args:
        alert (bytes): The alert information.

    Returns:
        None
    """
    print ("alert: ", alert)
    print("Alert TYYpe:", type(alert))
    print ("\n\n")
    alert = alert.replace(b'data: ', b'')
    alert_data = alert.decode('utf-8')

    print(alert_data)
    if alert_data != None:
        json_alert = json.loads(alert_data)
        print ("json_alert type  :  ", type(json_alert))
        url = serviceNowURL
        ticket_short_description = json_alert["ietf-restconf:notification"]["cisco-crosswork-service-health:service-health-notification"]["service-health-report"]["service-id"]
        ticket_description = json_alert["ietf-restconf:notification"]["cisco-crosswork-service-health:service-health-notification"]["service-health-report"]
        ticket_comments = 'Alright, team, our network has been moving slower than a snail on a coffee break! Lets give it a caffeine boost.'
        
        payload = '{"description": ticket_description, \
                    "short_description": "ticket_short_description", \
                    "comments": "ticket_comments", \
                    "urgency": "1"}'

        payload = payload.replace("ticket_description", alert_data)
        payload = payload.replace("ticket_short_description", str(ticket_short_description))
        payload = payload.replace("ticket_comments", str(ticket_comments))
        print("payload  :", payload)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Basic YWRtaW46UGFzczEyIzM0'
        }

        response = requests.request("POST", url, headers=headers, data = payload)

        # Checking response status
        if response.status_code == 201:
            print('Incident created successfully!')
        else:
            print('Failed to create incident. Status code:', response.status_code)
            print('Response:', response.text)


class Crosswork:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.crosswork_ip_address = config['crosswork']['ip_address']
        self.crosswork_port = config['crosswork']['port']
        self.crosswork_userid = config['crosswork']['userid']
        self.crosswork_password = config['crosswork']['password']
        self.crosswork_kpis = config['kpiprofile']['kpis']
        print ("Initializing    ")

    def get_ticket(self):
        """
        Retrieves a ticket from the Crosswork API.

        Returns:
            str: The ticket obtained from the API.

        Raises:
            requests.exceptions.RequestException: If an error occurs while making the API request.
        """
        logger.info('getTicket() : Getting Ticket')
        url = "https://" \
            + self.crosswork_ip_address \
            + ":" \
            + str(self.crosswork_port) \
            + "/crosswork/sso/v1/tickets/"
        querystring = {"username": self.crosswork_userid,
                    "password": self.crosswork_password}
        payload = ""
        response = requests.request("POST", url,
                                    data=payload,
                                    headers=Ticket_Token_Header,
                                    params=querystring,
                                    verify=False)
        logger.info('getTicket() : return code  :: %s', response.text)
        return response.text

    def get_token(self):
        """
        Retrieves a token from the Crosswork API.

        Returns:
            str: The token retrieved from the API.
        """
        logger.info('getToken() : Getting Token')
        url = "https://" \
            + self.crosswork_ip_address \
            + ":" + str(self.crosswork_port) \
            + "/crosswork/sso/v1/tickets/" \
            + self.get_ticket()
        payload = "service=https%3A%2F%2F" \
                + self.crosswork_ip_address \
                + "%3A30603%2Fapp-dashboard&undefined="
        response = requests.request("POST",
                                    url,
                                    data=payload,
                                    headers=Ticket_Token_Header,
                                    verify=False)
        logger.info('getToken() : return code  :: %s', response.text)
        return response.text

    def get_alert_notification_stream(self):
        """
        Retrieves the alert notification stream from CNC and processes the streaming data.

        Returns:
            None

        Raises:
            None
        """
        url = 'https://<IP Address of CWM>:30603/crosswork/nbi/cat-inventory/v1/restconf/notif/notification-stream/cisco-crosswork-service-health:service-health-notification/JSON'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': "Bearer " + self.get_token(),
        }
        print ('Headers: ', headers)
        with requests.request("GET", url, headers=headers, stream=True, verify=False) as response:
            if response.status_code == 200:
                for alert_data in response.iter_content(chunk_size=None):
                    # Process the streaming data here
                    print(alert_data)
                    print ("Alert Data size: ", len(alert_data))
                    #if len(alert_data) > 9:
                    if "symptom" in (str(alert_data)):
                        print ("Alert Data: ", alert_data)
                        create_servicenow_ticket(alert_data)
            else:
                print ("No data")
                print(f"Failed to get data. Status code: {response.status_code}")


def main():
    """
    The main function that executes the program.
    """
    cw = Crosswork()
    cw.get_alert_notification_stream()

if __name__== "__main__":
    main()
