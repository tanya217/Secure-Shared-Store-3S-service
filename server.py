import base64
import os
import time
from M2Crypto import m2, EVP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from os.path import isfile
from base64 import b64encode, b64decode
from urllib import response
from flask import Flask, request, jsonify
from flask_restful import Resource, Api


secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)
session_dict = dict()


class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"


class login(Resource):
    def post(self):
        data = request.get_json()
        print(data)
        # TODO: Implement login functionality
        user_id = data["user_id"]
        statement = data["statement"]
        encrypted_statement = SHA256.new(statement.encode())
        signed_statement = base64.b64decode(data["signed_statement"])

        """
        # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
        """
        try:
            user_public_key = RSA.import_key(
                open(os.getcwd() + "/userpublickeys/%s.pub" % (user_id), "r").read()
            )
            pkcs1_15.new(user_public_key).verify(encrypted_statement, signed_statement)
            success = user_id not in session_dict
        except (ValueError, TypeError) as e:
            print(e)
            success = False

        if success:
            session_token = base64.b64encode(
                m2.rand_bytes(32)
            )  # TODO: Generate session token
            # Similar response format given below can be used for all the other functions
            session_dict[user_id] = session_token.decode()
            response = {
                "status": 200,
                "message": "Login Successful",
                "session_token": session_token,
            }
        else:
            response = {"status": 700, "message": "Login Failed"}
        return jsonify(response)


class checkout(Resource):
    @staticmethod
    def confidentiality_read_and_decrypt(file_name, full_key):
        file_data = open(file_name, "rb").read()
        key = full_key[16:]
        iv = full_key[:16]
        print("Decrypt file_data: ", file_data, " key: ", key, " iv: ", iv)
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_file_data = aes_cipher.decrypt(file_data).strip(b"\x00").decode()
        return decrypted_file_data

    @staticmethod
    def integrity_read_and_decrypt(file_name):
        signed_file_data = b64decode(open(file_name + "_signed", "rb").read())
        file_data = open(file_name, "r").read()

        key = RSA.importKey(
            open(
                "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub"
            ).read()
        )
        sha = SHA256.new(file_data.encode())
        try:
            pkcs1_15.new(key).verify(sha, signed_file_data)
        except (ValueError, TypeError):
            return None

        return file_data

    @staticmethod
    def checkout_file(security_flag, file_name, key):
        document = None
        if security_flag == 1:
            document = checkout.confidentiality_read_and_decrypt(file_name, key)
        elif security_flag == 2:
            document = checkout.integrity_read_and_decrypt(file_name)
        return document

    def post(self):
        data = request.get_json()

        user_id = data["user_id"]
        file_name = "documents/" + data["did"]
        session_token = data["session_token"]
        metadata_file_name = file_name + ".meta"
        response_code = 700

        if not isfile(file_name):
            response_code = 704
        elif session_dict[user_id] == session_token:

            with open(metadata_file_name, "r") as temp_file:
                metadata = eval(temp_file.read())

            auth = metadata["auth"]
            key = b64decode(metadata["key"])
            security_flag = metadata["security_flag"]
            if security_flag not in [1, 2]:
                response_code = 700
            elif user_id == metadata["owner"]:
                document = self.checkout_file(security_flag, file_name, key)
                response_code = 200 if document else 703
            elif (
                user_id in auth
                and auth[user_id][0] in [2, 3]
                and int(time.time()) <= int(auth[user_id][1])
            ):
                document = self.checkout_file(security_flag, file_name, key)
                response_code = 200 if document else 703
            elif (
                0 in auth
                and auth[0][0] in [2, 3]
                and int(time.time()) <= int(auth[0][1])
            ):
                document = self.checkout_file(security_flag, file_name, key)
                response_code = 200 if document else 703
            else:
                response_code = 702

        else:
            success = 700

        """
        Expected response status codes
		1) 200 - Document Successfully checked out
		2) 702 - Access denied to check out
		3) 703 - Check out failed due to broken integrity
		4) 704 - Check out failed since file not found on the server
		5) 700 - Other failures
        """
        if response_code == 200:
            response = {
                "status": 200,
                "message": "Document Successfully checked out",
                "document": document,
            }
        elif response_code == 702:
            response = {"status": 702, "message": "Access denied to check out"}
        elif response_code == 703:

            response = {
                "status": 703,
                "message": "Check out failed due to broken integrity",
            }
        elif response_code == 704:
            print("Returning code 704")
            response = {
                "status": 704,
                "message": "Check out failed since file not found on the server",
            }
        else:
            print("Returning code 700")
            response = {"status": 700, "message": "Other failures"}

        return jsonify(response)


class checkin(Resource):
    @staticmethod
    def confidentiality_encrypt_and_save(file_name, file_data):
        full_key = m2.rand_bytes(32)
        key = full_key[16:]
        iv = full_key[:16]
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        file_length = len(file_data)
        padding = b"\x00" * (16 - (file_length % 16))
        aes_encrypted_file_data = aes_cipher.encrypt(file_data.encode() + padding)
        print(
            "Encrypt: file_data: ", aes_encrypted_file_data, " key: ", key, " iv: ", iv
        )
        with open(file_name, "wb") as temp_file:
            temp_file.write(aes_encrypted_file_data)
        return full_key

    @staticmethod
    def integrity_encrypt_and_save(file_name, file_data):
        key = RSA.importKey(
            open(
                "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key"
            ).read()
        )
        sha = SHA256.new(file_data.encode())
        signed_file_data = b64encode(pkcs1_15.new(key).sign(sha))
        with open(file_name + "_signed", "wb") as temp_file:
            temp_file.write(signed_file_data)
        with open(file_name, "w") as temp_file:
            temp_file.write(file_data)
        return "key"

    @staticmethod
    def checkin_file(security_flag, file_name, file_data):
        key = None
        if security_flag == 1:
            key = checkin.confidentiality_encrypt_and_save(file_name, file_data)
        elif security_flag == 2:
            key = checkin.integrity_encrypt_and_save(file_name, file_data)
        if key:
            return key

    def post(self):
        data = request.get_json()

        file_data = data["file_data"]
        user_id = data["user_id"]
        file_name = "documents/" + data["did"]
        security_flag = data["security_flag"]
        session_token = data["session_token"]
        metadata_file_name = file_name + ".meta"
        response_code = 700

        key = ""
        owner = data["user_id"]
        auth = dict()

        if session_dict[user_id] == session_token:
            if isfile(file_name):
                with open(metadata_file_name, "r") as temp_file:
                    metadata = eval(temp_file.read())

                owner = metadata["owner"]
                auth = metadata["auth"]

                if user_id == owner:
                    key = self.checkin_file(security_flag, file_name, file_data)
                    response_code = 200 if key else response_code
                elif (
                    user_id in auth
                    and auth[user_id][0] in [1, 3]
                    and int(time.time()) <= int(auth[user_id][1])
                ):
                    key = self.checkin_file(security_flag, file_name, file_data)
                    response_code = 200 if key else response_code
                elif (
                    0 in auth
                    and auth[0][0] in [1, 3]
                    and int(time.time()) <= int(auth[0][1])
                ):
                    key = self.checkin_file(security_flag, file_name, file_data)
                    response_code = 200 if key else response_code
                else:
                    response_code = 702

            else:
                key = self.checkin_file(security_flag, file_name, file_data)
                response_code = 200

        else:
            # Invalid session token
            response_code = 700

        """
        Expected response status codes:
        1) 200 - Document Successfully checked in
        2) 702 - Access denied to check in
        3) 700 - Other failures
        """
        if response_code == 200:
            print("key:", key)
            with open(metadata_file_name, "w") as temp_file:
                metadata = {
                    "owner": owner,
                    "key": b64encode(key) if key != "key" else "",
                    "security_flag": security_flag,
                    "auth": auth,
                }
                temp_file.write(str(metadata))

            response = {
                "status": 200,
                "message": "Check In Successful",
                "session_token": session_token,
            }

        elif response_code == 702:
            response = {"status": 702, "message": "Access Denied"}
        else:
            response_code = {"status": 700, "message": "Other failure"}

        return jsonify(response)


class grant(Resource):
    def post(self):
        data = request.get_json()

        user_id = data["user_id"]
        target_user = data["target_user"]
        access_right = data["access_right"]
        time_duration = data["time_duration"]
        metadata_file_name = "documents/" + data["did"] + ".meta"
        session_token = data["session_token"]
        response_code = 700
        # my_dict.pop('key', None)

        end_time = int(time.time()) + time_duration

        if not isfile(metadata_file_name):
            response_code = 700
        elif session_dict[user_id] == session_token:
            with open(metadata_file_name, "r") as temp_file:
                metadata = eval(temp_file.read())
            if user_id != metadata["owner"]:
                response_code = 702
            else:
                for k in list(metadata["auth"].keys()):
                    if int(metadata["auth"][k][1]) < int(time.time()):
                        metadata["auth"].pop(k)
                if target_user == "0":
                    metadata["auth"] = {0: (int(access_right), end_time)}
                else:
                    metadata["auth"][target_user] = (int(access_right), end_time)

                with open(metadata_file_name, "w") as temp_file:
                    temp_file.write(str(metadata))
                response_code = 200

        else:
            response_code = 700

        if response_code == 200:
            response = {"status": 200, "message": "Successfully granted access"}
        elif response_code == 702:
            response = {"status": 702, "message": "Access denied to grant access"}
        else:
            response = {"status": 700, "message": "Other failures"}
        # TODO: Implement grant functionality
        """
		Expected response status codes:
		1) 200 - Successfully granted access
		2) 702 - Access denied to grant access
		3) 700 - Other failures
	    """
        return jsonify(response)


class delete(Resource):
    def post(self):
        data = request.get_json()

        user_id = data["user_id"]
        file_name = "documents/" + data["did"]
        metadata_file_name = "documents/" + data["did"] + ".meta"
        session_token = data["session_token"]
        response_code = 700

        if not isfile(file_name):
            response_code = 704
        elif session_dict[user_id] == session_token:
            with open(metadata_file_name, "r") as temp_file:
                metadata = eval(temp_file.read())
            if user_id != metadata["owner"]:
                response_code = 702
            else:
                os.remove(file_name)
                os.remove(metadata_file_name)
                response_code = 200
        else:
            response_code = 700

        if response_code == 200:
            response = {"status": 200, "message": "Successfully deleted the file"}
        elif response_code == 702:
            response = {"status": 702, "message": "Access denied to delete file"}
        elif response_code == 704:
            response = {
                "status": 704,
                "message": "Delete failed since file not found on the server",
            }
        else:
            response = {"status": 700, "message": "Other failures"}
        # TODO: Implement grant functionality
        """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied to delete file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
        """
        return jsonify(response)


class logout(Resource):
    def post(self):
        data = request.get_json()

        user_id = data["user_id"]
        session_token = data["session_token"]
        response_code = 700

        if session_dict[user_id] == session_token:
            session_dict.pop(user_id)
            response_code = 200
        else:
            response_code = 700

        if response_code == 200:
            response = {"status": 200, "message": "Successfully logged out"}
        else:
            response = {"status": 700, "message": "Failed to log out"}
        # TODO: Implement grant functionality
        """
		Expected response status codes:
		1) 200 - Successfully logged out
		2) 700 - Failed to log out
	    """
        return jsonify(response)


api.add_resource(welcome, "/")
api.add_resource(login, "/login")
api.add_resource(checkin, "/checkin")
api.add_resource(checkout, "/checkout")
api.add_resource(grant, "/grant")
api.add_resource(delete, "/delete")
api.add_resource(logout, "/logout")


def main():
    secure_shared_service.run(debug=True)


if __name__ == "__main__":
    main()
