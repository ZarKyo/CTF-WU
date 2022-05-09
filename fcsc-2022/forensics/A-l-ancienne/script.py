import pyshark
from base64 import b64decode

last_qry = ""
data = {}
      
with pyshark.FileCapture('./cap', display_filter=('dns')) as packets:

    packets.load_packets()

    for pkt in packets:

      # parsing
      qry = pkt.dns.qry_name

      qry = qry.replace("*","+").strip().split("-.")
      filename = qry[-1]
      qry = ''.join(qry)
      qry = qry.replace(filename,"").strip()  
      
      if last_qry != qry:

        if filename not in data:
          data[filename] = qry
        else:
          data[filename] += qry

      last_qry = qry

for key,value in data.items():
    with open(f'files/{b64decode(key).decode()}.gz','wb+') as f:
        f.write(b64decode(value))