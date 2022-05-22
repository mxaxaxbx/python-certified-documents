from PDFNetPython3.PDFNetPython import *
from PDFNetPython3.PDFNetPython import Image
from typing import Tuple

import OpenSSL
import os
import time
import argparse

def create_key_pair(type, bits):
  pkey = OpenSSL.crypto.PKey()
  pkey.generate_key(type, bits)
  return pkey

def create_self_signed_cert(pKey):
  # Create a self signed certificate
  cert = OpenSSL.crypto.X509()
  # Common Name (eg "www.example.com")
  cert.get_subject().CN = "localhost"
  # serial number
  cert.set_serial_number(int(time.time() * 10))
  # not before
  cert.gmtime_adj_notBefore(0) # not before
  # not after (Expire after 10 years)
  cert.gmtime_adj_notAfter(10*365*24*60*60)
  # Identity issue
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(pKey)
  cert.sign(pKey, 'md5') # or cert.sign(pKey, 'sha256')
  return cert

def load():
  summary = {}
  summary['OpenSSL Version'] = OpenSSL.version.__version__
  # Generating a Private Key
  key = create_key_pair(OpenSSL.crypto.TYPE_RSA, 2048)
  # PEM encoded
  with open('private.pem', 'wb') as f:
    pk_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    f.write(pk_str)
    summary['Private Key'] = pk_str
  # Done - Generating a Private Key...
  # Generating a self-signed client certification...
  cert = create_self_signed_cert(key)
  with open('certificate.cer', 'wb') as cer:
    cert_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    cer.write(cert_str)
    summary['Self signed certificate'] = cert_str
  # Done - Generating a self-signed client certification...
  # Generating the public key...
  with open('public.pem', 'wb') as pub_key:
    pub_key_str = OpenSSL.crypto.dump_publickey(
      OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()
    )
    pub_key.write(pub_key_str)
    summary['Public Key'] = pub_key_str
  # Done - Generating the public key...
  # Take a private key and certificate and create a PKCS12 file
  # Generating a container file of the private key and certificate...
  p12 = OpenSSL.crypto.PKCS12()
  p12.set_privatekey(key)
  p12.set_certificate(cert)
  open('container.pfx', 'wb').write(p12.export())
  # You make convert a PKSC12 file (.pfx) to a PEM fromat
  # Done - Generating a container file of the private key and certificate...
  # To display a summary
  print('## Initialization Summary ##')
  print('\n'.join("{}:{}".format(i, j) for i, j in summary.items()))
  print('############################')
  return True

def sign_file(input_file:str, signatureID:str, x_coordinate:int, y_coordinate:int, pages:Tuple, output_file:str=None):
  # An output file is automatically generated with
  # the word signed added at its end
  if not output_file:
    output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"
  
  # Initialize the library
  PDFNet.Initialize()
  doc = PDFDoc(input_file)
  # Create a signature field
  sig_field = SignatureWidget.Create(doc, Rect(
    x_coordinate, y_coordinate, x_coordinate+100, y_coordinate+50
  ), signatureID)
  # Iterate throughout document pages
  for page in range(1, (doc.GetPageCount() + 1)):
    # If required for specific pages
    if pages:
      if str(page) not in pages:
        continue
    pg = doc.GetPage(page)
    # Create a signature text field and push on the page
    pg.AnnotPushBack(sig_field)
  # Signature image
  sign_filename = os.path.dirname(
    os.path.abspath(__file__)
  ) + "/signature.png"
  # Self signed certificate
  pk_filename = os.path.dirname(
    os.path.abspath(__file__)
  ) + "/container.pfx"
  # Retrieve the signature field
  approval_field = doc.GetField(signatureID)
  approval_signature_digsig_field = DigitalSignatureField(approval_field)
  # Add apperance to the signature field
  img = Image.Create(doc.GetSDFDoc(), sign_filename)
  found_approval_signature_widget = SignatureWidget(
    approval_field.GetSDFObj()
  )
  found_approval_signature_widget.CreateSignatureAppearance(img)
  # Prepare the signature and signature handler for signing
  approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
  # The signing will be done during the following incremental save operation.
  doc.Save(output_file, SDFDoc.e_incremental)
  # Develop a process summary
  summary = {
    "Input File": input_file, "Signature ID": signatureID, 
    "Output File": output_file, "Signature File": sign_filename, 
    "Certificate File": pk_filename
  }
  # Printing summary
  print('## Summary ##')
  print('\n'.join("{}:{}".format(i, j) for i, j in summary.items()))
  print('############################')
  return True

def is_valid_path(path):
  if not os.path.exists(path):
    raise argparse.ArgumentTypeError( "The path {} does not exist".format(path) )
  # check if the path is a file
  if not os.path.isfile(path):
    raise argparse.ArgumentTypeError( "The path {} is not a file".format(path) )
  
  # check if the file is a pdf
  if not path.endswith('.pdf'):
    raise argparse.ArgumentTypeError( "The file {} is not a pdf".format(path) )
  
  # check if the file is readable
  if not os.access(path, os.R_OK):
    raise argparse.ArgumentTypeError( "The file {} is not readable".format(path) )
  
  return path

def parse_args():
  parser = argparse.ArgumentParser(description="Available Options")
  parser.add_argument('-l', '--load', dest='load', action="store_true",
                      help="Load the required configurations and create the certificate")
  parser.add_argument('-i', '--input_path', dest='input_path', type=is_valid_path,
                      help="Enter the path of the file or the folder to process")
  parser.add_argument('-s', '--signatureID', dest='signatureID',
                      type=str, help="Enter the ID of the signature")
  parser.add_argument('-p', '--pages', dest='pages', type=tuple,
                      help="Enter the pages to consider e.g.: [1,3]")
  parser.add_argument('-x', '--x_coordinate', dest='x_coordinate',
                      type=int, help="Enter the x coordinate.")
  parser.add_argument('-y', '--y_coordinate', dest='y_coordinate',
                      type=int, help="Enter the y coordinate.")
  path = parser.parse_known_args()[0].input_path
  if path and os.path.isfile(path):
      parser.add_argument('-o', '--output_file', dest='output_file',
                          type=str, help="Enter a valid output file")
  if path and os.path.isdir(path):
      parser.add_argument('-r', '--recursive', dest='recursive', default=False, type=lambda x: (
          str(x).lower() in ['true', '1', 'yes']), help="Process Recursively or Non-Recursively")
  args = vars(parser.parse_args())
  # To Display The Command Line Arguments
  print("## Command Arguments #################################################")
  print("\n".join("{}:{}".format(i, j) for i, j in args.items()))
  print("######################################################################")
  return args

if __name__ == '__main__':
  # Parsing command line arguments entered by user
  args = parse_args()
  if args['load'] == True:
    load()
  else:
    # If File Path
    if os.path.isfile(args['input_path']):
      sign_file(
        input_file=args['input_path'], signatureID=args['signatureID'],
        x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']), 
        pages=args['pages'], output_file=args['output_file']
      )
