# Goal

Establish ssl connection with the server using "mutual tls"/"2-way ssl" authentication 

# Problem statement

Client sends the latest added certificate in keystore to the server

Cases:

- If there are **single** certificate in client's keystore -> authentication would work until new certificate is added
- If there are **multiple** certificates in client's keystore -> we need to tell explicitly which certificate should be used for ssl connection

# Solution

Implement key manager to tell which certificate to use for ssl connection

# Key benefit

While it's relatively simple to implement a key manager, the main benefit is to show the cases when ssl connection works and when it's not

For anyone who solves the same issue this **library would allow NOT to write additional tests** to check that connection really works