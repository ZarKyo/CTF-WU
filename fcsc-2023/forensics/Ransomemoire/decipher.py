import os

def xor_files(file1, file2, output_file, i2):
    with open(file1, "rb") as f1, open(file2, "rb") as f2, open(output_file, "wb") as out:
        buffer_file = f1.read()
        buffer_file2 = f2.read()
        value_100 = len(buffer_file)

        i = 0
        while i != value_100:
            byte1 = buffer_file[i]
            byte2 = buffer_file2[i]
            out.write(bytes([byte1 ^ byte2 ^ i2]))
            i = i + 1

# Input and output file paths
flag_file = "extracts/flag.fcsc.enc"
output_folder = "output"

# Create output folder if it doesn't exist
if not os.path.exists(output_folder):
    os.mkdir(output_folder)

# Loop over MsCmdRunX.log files in Log folder
for i in range(20):
    log_file = f"log/MsCmdRun{i}.log"
    output_file = f"{output_folder}/xor_output{i}.txt"

    # Perform the XOR operation between the flag file and the log file
    xor_files(flag_file, log_file, output_file, i)

    print(f"Le fichier {log_file} a été XOR avec succès avec le fichier {flag_file}")
    print(f"Le résultat est enregistré dans {output_file}")
