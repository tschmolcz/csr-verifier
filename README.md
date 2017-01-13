# csr-verifier
X.509-CSR Verification APP

The CSR verifier app allows to verify one set of x.509 attributes against a folder of "Certificate Signed Request"-Files. Incorrect CSRs are get marked by renaming the specific filename.

Input requires the x.509 attributes and the path to the CSR files as well as to the "Common Name" textfile list (comma-seperated) with the different Common Names (CNs)

Moduls os and OpenSS.crypto are used.
