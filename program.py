import OpenSSL.crypto as crypto
import os


def print_header():
    print("----------------------------------------------------------------")
    print("------------------------X.509-CSR Verifier APP------------------")
    print("----------------------------------------------------------------\n")


def request_userinput():
    x509attr = [ ]

    print("Define the x509 attributes\n")
    x509attr.append(verify_input(input("Organization Name: ")))
    x509attr.append(verify_input(input("Organizational Unit: ")))
    x509attr.append(verify_input(input("Country: ")))
    x509attr.append(verify_input(input("State: ")))
    x509attr.append(verify_input(input("Location: ")))
    x509attr.append(verify_input(input("Certificate Key size: ")))

    print("\nX.509 attributes saved.")

    csrpath = os.path.abspath(input("\nPath to the CSRs Folder:  "))

    cnpath = os.path.abspath(input("\nPath to the CN text file (comma separated text-file):  "))

    print("\nPaths values saved.")

    return x509attr, csrpath, cnpath


def verify_input(data):
    if data.split():
        pass
    else:
        while not data:
            data = input("\nNothing has been entered. Please set a value:  ")

    return data


def read_paths(csrpath, cnpath):
    csrlist = [ ]
    cnlist = [ ]

    try:

        for item in os.listdir(csrpath):
            csrlist.append(csrpath + "\\" + item) if ".csr" in item else None

        for item in os.listdir(cnpath):
            cnlist.append(cnpath + "\\" + item) if ".txt" in item else None

        return csrlist, cnlist

    except FileNotFoundError:

        print("\nNo CSR files could be found with the given path: {}\n".format(FileNotFoundError))


def read_files(csrlist, cnlist):
    all_certs = [ ]

    for item in csrlist:
        with open(item, 'r', encoding='utf-8') as fin:
            file = fin.read()

            request = crypto.load_certificate_request(crypto.FILETYPE_PEM, file)

            subject = request.get_subject()

            key = request.get_pubkey()

            attributes = dict(subject.get_components())
            attributes[ b'O' ] = str(attributes[ b'O' ]).strip('b\'')
            attributes[ b'OU' ] = str(attributes[ b'OU' ]).strip('b\'')
            attributes[ b'C' ] = str(attributes[ b'C' ]).strip('b\'')
            attributes[ b'ST' ] = str(attributes[ b'ST' ]).strip('b\'')
            attributes[ b'L' ] = str(attributes[ b'L' ]).strip('b\'')
            attributes[ b'CN' ] = str(attributes[ b'CN' ]).lower().strip('b\'')
            attributes[ 'k' ] = str(key.bits())

            all_certs.append(attributes)

    for item in cnlist:
        with open(item, 'r', encoding='utf-8') as fin:
            file = fin.read()

            cnvalues = file.lower().split(',')

    return all_certs, cnvalues


def verify_certs(all_certs, x509attr, csrlist, cnvalues):
    invalid_files = [ ]

    for key, item in enumerate(all_certs):

        if x509attr[ 0 ] == item[ b'O' ] and x509attr[ 1 ] == item[ b'OU' ] and x509attr[ 2 ] == item[ b'C' ] and \
                        x509attr[ 3 ] == item[ b'ST' ] and x509attr[ 4 ] == item[ b'L' ] and x509attr[ 5 ] == item[
            'k' ]:

            if item[ b'CN' ] in cnvalues:
                pass
            else:
                invalid_files.append(csrlist[ key ])
        else:
            invalid_files.append(csrlist[ key ])

    return invalid_files


def display_results(results, csrlist):
    if results:
        print(
            "\nThe following 'Certificate Signing Requests' are invalid and their filename has been marked with 'wrong' :\n ")

    for file in results:
        fname = (str(file).split('\\'))
        print(fname[ len(fname) - 1 ])
        os.rename(file, file + "_wrong")

    else:
        print("\nAll {} 'Certificate Signing Requests' are valid.".format(len(csrlist)))


def main():
    print_header()

    x509attr, csrpath, cnpath = request_userinput()

    csrlist, cnlist = read_paths(csrpath, cnpath)

    all_certs, cnvalues = read_files(csrlist, cnlist)

    results = verify_certs(all_certs, x509attr, csrlist, cnvalues)

    display_results(results, csrlist)


if __name__ == '__main__':
    main()
