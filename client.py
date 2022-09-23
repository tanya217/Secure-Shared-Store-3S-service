import base64
import requests
import certifi
import os
import shutil
import json
from M2Crypto import m2, X509
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from os.path import isfile
from glob import glob
from time import time


gt_username = "tsharma61"  # TODO: Replace with your gt username within quotes
server_name = "secure-shared-store"

""" <!!! DO NOT MODIFY THIS FUNCTION !!!>"""


def post_request(server_name, action, body, node_certificate, node_key):
    """
    node_certificate is the name of the certificate file of the client node (present inside certs).
    node_key is the name of the private key of the client node (present inside certs).
    body parameter should in the json format.
    """
    request_url = "https://{}/{}".format(server_name, action)
    request_headers = {"Content-Type": "application/json"}
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
    )
    with open(gt_username, "wb") as f:
        f.write(response.content)
    return response


def get_client_id():
    cwd = os.getcwd()
    if cwd.endswith("client1"):
        return "1"
    return "2"


""" You can begin modification from here"""


def login():
    """
    # TODO: Accept the
        - user-id
        - name of private key file(should be
    present in the userkeys folder) of the user.
    Generate the login statement as given in writeup and its signature.
    Send request to server with required parameters (action = 'login') using
    post_request function given.
    The request body should contain the user-id, statement and signed statement.
    """
    user_id = input("Enter user id: ")
    cwd = os.getcwd()
    cid = get_client_id()
    user_key_file = cwd + "/userkeys/" + input("Enter key file name: ")
    statement = "Client" + cid + " as " + user_id + " logs into the Server"

    client_cert_file = cwd + "/certs/client" + cid + ".crt"
    client_key_file = cwd + "/certs/client" + cid + ".key"

    print(client_cert_file)
    print(client_key_file)

    try:
        r_key = RSA.importKey(open(user_key_file, "r").read())
    except:
        print("User or Key Invalid")
        login()
        return
    encrypted_statement = SHA256.new(statement.encode())
    signed_statement = pkcs1_15.new(r_key).sign(encrypted_statement)

    body = {
        "user_id": user_id,
        "statement": statement,
        "signed_statement": (base64.b64encode(signed_statement)).decode(),
    }
    print(body)

    response = (
        post_request(server_name, "login", body, client_cert_file, client_key_file)
    ).json()

    if response["status"] != 200:
        print(response["message"])
        login()
        return

    global current_user
    global session_token
    current_user = user_id
    session_token = response["session_token"]

    for x in glob("/documents/checkout/*"):
        os.remove(x)

    return


def checkin(did=None, security_flag=0):
    """
    # TODO: Accept the
        - DID
        - security flag (1 for confidentiality  and 2 for integrity)
    Send the request to server with required parameters (action = 'checkin') using post_request().
    The request body should contain the required parameters to ensure the file is sent to the server.
    """
    if not did:
        did = input("Enter the document ID: ")
        security_flag = int(
            input("Enter security flag - 1 (Confidentiality), 2 (Integrity)")
        )

    cwd = os.getcwd()
    cid = get_client_id()

    client_cert_file = cwd + "/certs/client" + cid + ".crt"
    client_key_file = cwd + "/certs/client" + cid + ".key"

    checkin_path = cwd + "/documents/checkin/" + did
    checkout_path = cwd + "/documents/checkout/" + did

    print(checkin_path, checkout_path)

    if os.path.isfile(checkout_path):
        # File exists in checkout
        shutil.move(checkout_path, checkin_path)
    data = open(checkin_path, "r").read()

    body = {
        "user_id": current_user,
        "did": did,
        "file_data": open(checkin_path, "r").read(),
        "session_token": session_token,
        "security_flag": security_flag,
    }
    print(body)
    response = (
        post_request(server_name, "checkin", body, client_cert_file, client_key_file)
    ).json()
    print(response)
    return


def checkout():
    """
    # TODO: Accept the DID.
    Send request to server with required parameters (action = 'checkout') using post_request()
    """
    did = input("Enter the Document ID: ")

    cwd = os.getcwd()
    cid = get_client_id()

    client_cert_file = cwd + "/certs/client" + cid + ".crt"
    client_key_file = cwd + "/certs/client" + cid + ".key"

    checkout_path = cwd + "/documents/checkout/" + did

    body = {
        "user_id": current_user,
        "did": did,
        "session_token": session_token,
    }
    response = (
        post_request(server_name, "checkout", body, client_cert_file, client_key_file)
    ).json()
    if response["status"] == 200:
        with open(checkout_path, "w") as temp_file:
            temp_file.write(response["document"])
    else:
        print(response["status"], response["message"])

    return


def grant():
    """
    # TODO: Accept the
        - DID
        - target user to whom access should be granted (0 for all user)
        - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
        - time duration (in seconds) for which acess is granted
    Send request to server with required parameters (action = 'grant') using post_request()
    """
    did = input("Enter the Document ID: ")
    target_user = input("Enter the target user (Enter 0 for all users): ")
    access_right = int(
        input("Enter the access right (1- Checkin, 2-Checkout, 3- Both): ")
    )
    time_duration = int(input("Enter the grant time duration in seconds: "))

    cwd = os.getcwd()
    cid = get_client_id()

    client_cert_file = cwd + "/certs/client" + cid + ".crt"
    client_key_file = cwd + "/certs/client" + cid + ".key"

    body = {
        "user_id": current_user,
        "did": did,
        "target_user": target_user,
        "access_right": access_right,
        "time_duration": time_duration,
        "session_token": session_token,
    }
    response = (
        post_request(server_name, "grant", body, client_cert_file, client_key_file)
    ).json()

    print(response["status"], response["message"])

    return


def delete():
    """
    # TODO: Accept the DID to be deleted.
    Send request to server with required parameters (action = 'delete')
    using post_request().
    """
    doc_id = input("Enter the Document ID: ")

    cwd = os.getcwd()
    cid = get_client_id()

    client_cert_file = cwd + "/certs/client" + cid + ".crt"
    client_key_file = cwd + "/certs/client" + cid + ".key"

    body = {
        "user_id": current_user,
        "did": doc_id,
        "session_token": session_token,
    }

    response = (
        post_request(server_name, "delete", body, client_cert_file, client_key_file)
    ).json()
    print(response["status"], response["message"])

    return


def logout():
    """
    # TODO: Ensure all the modified checked out documents are checked back in.
    Send request to server with required parameters (action = 'logout') using post_request()
    The request body should contain the user-id, session-token
    """

    cwd = os.getcwd()
    cid = get_client_id()

    client_cert_file = cwd + "/certs/client" + cid + ".crt"
    client_key_file = cwd + "/certs/client" + cid + ".key"

    checkout_files_path = cwd + "/documents/checkout/"

    body = {
        "user_id": current_user,
        "session_token": session_token,
    }

    files = [
        f
        for f in os.listdir(checkout_files_path)
        if isfile(os.path.join(checkout_files_path, f))
    ]

    for f in files:
        checkin(f, 2)

    response = (
        post_request(server_name, "logout", body, client_cert_file, client_key_file)
    ).json()
    print(response["status"], response["message"])

    exit()  # exit the program


def main():
    """
    If the login is successful, provide the following options to the user
        1. Checkin
        2. Checkout
        3. Grant
        4. Delete
        5. Logout
    The options will be the indexes as shown above. For example, if user
    enters 1, it must invoke the Checkin function. Appropriate functions
    should be invoked depending on the user input. Users should be able to
    perform these actions in a loop until they logout. This mapping should
    be maintained in your implementation for the options.
    """
    with open("../CA/CA.crt", "rb") as f1:
        with open(certifi.where(), "ab") as f2:
            f2.write(f1.read())
    try:
        login()
        while True:

            print("Welcome to the secure shared store client:")
            print("Please select an option:")
            print("1. Checkin")
            print("2. Checkout")
            print("3. Grant")
            print("4. Delete")
            print("5. Logout")

            option = int(input("Option: "))

            if option == 1:
                checkin()
            elif option == 2:
                checkout()
            elif option == 3:
                grant()
            elif option == 4:
                delete()
            elif option == 5:
                logout()
            else:
                print("Try again. Invalid")

    except Exception as e:
        print("Error - %s. Please try again " % e)
        logout()


if __name__ == "__main__":
    main()
