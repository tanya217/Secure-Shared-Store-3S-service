# Secure-Shared-Store-3S-service
Task: Develop a simple Secure Shared Store (3S) service that allows for the storage and retrieval of documents created by multiple users who access the documents at their local machines. The system consistS of one or more 3S client nodes and a single server that stores the documents. Users should be able to login to the 3S server through any client by providing their private key. Session tokens would be generated upon successful authentication of the users. They can then check-in, checkout and delete documents as allowed by access control policies defined by the owner of the document.

Solution:

Architectural design details:
a. How mutual authentication is achieved in the current implementation of 3S.
i. User authentication:
1. The user is first required to enter their user ID and the name of the private key file in order to issue a request to the server through the client.
2. The client then looks for the private key at ‘/home/cs6238/Desktop/Project4/client-x/userkeys/’ and generates the statement, ‘ClientX as UserY logs into the Server’. If the key is found, the client sends the statement (after signing with the user’s private key), the original statement and the user ID to the server.
ii. Client authentication:
1. The client sends its private key and location of its certificate to the server for its authentication before sending the data of the user.
iii. Server:
1. The server validates the signed document by using the user’s public key.
2. A session token is created for the user after verification and sent to the client.
3. The server finally retrieves the data.
iv. The entire authentication process is undertaken by Flask and implementation of Secure Shared Store (3S) service uses nginx mutual TLS.

Details on the cryptographic libraries and functions used to handle secure file storage

Confidentiality - The current implementation makes use of some procedures from different modules to ensure that the content of the files shared between the user and the
server is not available to anyone without the access.
1. Modules:
a. M2Crypto
b. Crypto
2. Procedures:
a. encrypt() - file encryption (using CBC mode)
b. AES.new() - file encryption (using CBC mode)
c. M2Crypto.m2.rand_bytes() - randomization for the Initialization Vector (IV)
and the key
d. cipher.decrypt() - file decryption

Integrity - The current implementation makes use of some procedures from different modules to ensure that the files shared between the user and the server are not
modified by anybody else.
1. Modules:
a. Crypto
b. M2Crypto
2. Procedures:
a. SHA256.new() - used for hashing the file.
b. RSA.importKey() - used to import the private key of the server.
c. Crypto.Signature.pkcs1_15.new() - used to sign the file’s hash with the
server’s private key.

How were the user information and metadata related to documents were stored?
i. The ‘‘/documents’ folder within the server stores the documents and their corresponding metadata. Once the user checks in a file, it gets stored at the server along with its metadata. The following details of the document are stored using a dictionary:
1. Key and IV (first 16 - IV and last 16 - Key) used for encryption
2. File owner
3. Security flag that was given by the user
4. A sub-dictionary to store the grant details who are allowed to access the file and
duration for which they are allowed to access the file.
5. The document signed by the server.

Implementation details:
a. Details of how the required functionalities were implemented.

i. login( ):
1. User authentication:
a. The user is first required to enter their user ID and the name of the private key file in order to issue a request to the server through the client.
b. The client then looks for the private key at ‘/home/cs6238/Desktop/Project4/clientx/userkeys/’ and generates the statement, ‘ClientX as UserY logs into the Server’. If the key is found, the client sends the statement (after signing with the user’s private key), the original statement and the user ID to the server.
2. Client authentication:
a. The client sends its private key and location of its certificate to the server for its authentication before sending the data of the user.
3. Server:
a. The server validates the signed document by using the user’s public key.
b. A session token is created for the user after verification and sent to the client.
4. A user is not allowed to login from different clients. If the user attempts that, it fails
5. If the user login fails, they are asked to login again.

ii. checkin( ):
1. When the user raises a request to checkout a document the client sends the
following details to the server -
a. UserID
b. Session token
c. Document DID
2. The server checks if the document already exists on the server. The current user is set as the owner and a new file is created if the file is not found.
3. If the file is found and the given user ID is either the owner of the document or has the permission to check in the document, the server makes the following
security flag checks.
4. A security flag value set to 1, indicates confidentiality. The file is encrypted and stored at the server using encrypt() and AES.new().
M2Crypto.m2.rand_bytes(32) is used to obtain randomization for the key(16) and IV(16).
5. A security flag value set to 2, indicates integrity. The following tasks are the
executed -
a. SHA256.new() - used for hashing the file.
b. RSA.importKey() - used to import the private key of the server.
c. Crypto.Signature.pkcs1_15.new() - used to sign the file’s hash with the
server’s private key.
6. Based on the value of the security flag, one of the two (point 4 or point 5) are
executed.
7. The file is stored at the server along with its metadata. The details of the users who have access to the check in the file is maintained with the help of a
dictionary at the server.
8. If a user without a permission tries to check in, a status code value of 702 is returned.

ii. checkout( ):
1. When the user raises a request to checkout a document the client sends the
following details to the server -
a. UserID
b. Session Token
c. Document DID
2. The server checks if the document already exists on the server. If the document is found, the user is given the permission provided the user id if coming from a
user who is either the owner of the document or has the access right.
3. The next check is the duration window. The server checks if the duration window for the permit is valid and grants access.
4. If the document is stored at the server with the security flag value set to 1, indicating confidentiality, the server performs decryption on the file using the key
and the IV that is stored in the document’s metadata. The file is then sent to the client after decryption.
5. The file is stored as a signed document if the document is stored at the server with the security flag value set to 2 which indicates integrity. Once the server
ensures that the file is not compromised by validating the signature using the public key and comparing the hashed value with the original file hash, the file is
sent to the client.
6. If the file does not already exist at the server, a status code of 704 is returned
indicating the file is not found.

iv. grant( ):
1. Only the owner of a file can grant access to other users to access the file. Therefore, when a user (owner of the file) raises a request to grant access to
others, the client needs the following information -
a. File name (whose permissions need to be granted to another user)
b. User (the access would be granted to this user after the operation)
c. Permissions (checkin | checkout | both checkin and checkout)
d. Duration for which the permissions are granted.
We use a dictionary to store thisAuth = {‘user1’: (1, xxxxxx)} where 1-> CheckIn access only, xxxxxx-Aboslute epoch time of access expiry User1 - > UserID (Could be 0 for all users)
2. The server first checks if the user ID given by the client is the owner of the file.
3. The users and the duration for which they are able to perform the operation are added to the dictionary.
4. If the user tries to perform the action beyond the duration window, the access granted is lost. The most recent granted access within the duration window is
retained.

v. delete( ):
1. Only the owner of a file should be able to delete it. Therefore, when a user raises a request to delete a file, the server first checks for the validity of the session token and if the user owns the file.
2. On successful validation and if the file exists on the server, the file along with its metadata is deleted from the ‘/documents’ folder in the server.
3. A status code of 200 is returned on successful deletion and the file is also deleted from the client side.

logout( ):
1. The user ID and their session token is sent by the client to the server when the user issues a request to log out.
2. The session token is then verified by the server for that user.
3. On successful verification, the server ends the session by deleting the session token and returning with a status code of 200 indicating that the user has logged
out successfully.
4. The documents that were checked out by the user are verified, signed by the server and stored at the server and at the checkin directory within the client.

Static code analysis
pylin was used to ensure that the code does not have any vulnerabilities.

Results of the static code analysis and the tools used.
i. Scope for improvement - the loop time complexity and the naming conventions adopted throughout the program can be made efficient.
ii. Client.py
1. Rating - 6.71/10

iii. server.py
1. Rating - 5.1/10

Threat modeling
a. Threat Modeling and the threats currently handled by our implementation.
i. Instances of threat scenarios that are not handled under the current implementation:
1. The user login is currently highly dependent on the user’s private key and hence it is not possible for a user to login without their private key.
2. Gaining access to the user data through social engineering attacks is a valid
concern.
3. If the server is compromised, all the documents with integrity flag are compromised since the data is stored as it is.
4. The client code uses getcwd to determine the client number. This could be dangerous
ii. Instances of threat scenarios that are handled under the current implementation:
1. When the connection between the client and the server is established, there is a session key generated which verifies that current session and helps in preventing
man in the middle attacks.
2. In the current implementation, the identity of any client is verified with the help of their certificate and private key which helps in avoiding impersonation of one cient as another.
3. The current implementation requires mentioning a security flag for every file that
is being checked in. The flag can either imply confidentiality or integrity of the file.
This feature helps us in ensuring that the file data is unmodified and is accessible
only to the users who are authorized to access its contents.
4. The delete function wipes out the entire data of a file that is stored on the server.
5. All the details related to a file, including the name of the owner and the users who
have access to its content are stored in the file metadata on the server. This
ensures that only the users with the file access are allowed to access the file
contents.
6. The client creates a user account with the help of their private key and the server
uses the user’s public key to validate the user. This ensures no other user can
impersonate another user
