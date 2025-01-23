print '''
[+] by jnqpblc
'''
import argparse
import os

# Function to check if the input file exists
def validate_file(file_path):
    if not os.path.isfile(file_path):
        raise argparse.ArgumentTypeError(f"The file '{file_path}' does not exist or is not a valid file.")
    return file_path

# Argument parser setup
parser = argparse.ArgumentParser(description="Convert a PowerShell script to a BadUSB Script.")
parser.add_argument(
    '-s', "--ps1_script_file",
    type=validate_file,
    help="Path to the existing PowerShell (.ps1) file to be converted.",
    required=True,
)
parser.add_argument(
    '-o', "--output_badusb_script",
    type=str,
    help="Path to save the converted BadUSB Script file. Defaults to replacing .ps1 with .txt.",
    required=True,
)
parser.add_argument(
    '-d', "--script_typing_delay",
    type=str,
    help="Millisecond delay in between chucks of 95 chars for long lines.",
    default="500",
)

args = parser.parse_args()

# Define paths
existing_ps1_file = args.ps1_script_file
output_badusb_script = args.output_badusb_script or existing_ps1_file.replace(".ps1", ".txt")
script_delay = args.script_typing_delay

# Read the contents of the existing PowerShell script
with open(existing_ps1_file, "r", encoding="utf-8") as file:
    ps1_contents = file.readlines()

# Initialize the BadUSB Script variable
badusb_script = []

# Convert each line of the PowerShell script to BadUSB Script
for line in ps1_contents:
    # Remove leading and trailing whitespace from the line
    line = line.strip()

    # Ignore empty lines or lines starting with '#'
    if line and not line.startswith("#"):
        # Split the line into chunks of 95 characters
        for i in range(0, len(line), 95):
            chunk = line[i:i + 95]
            badusb_script.append(f"STRING {chunk}")
            # Add ENTER and BACKSPACE after each chunk
            badusb_script.append("ENTER")
            badusb_script.append("BACKSPACE")
            badusb_script.append(f"DELAY {script_delay}")
        badusb_script.append("ENTER")

# Write the BadUSB Script to the output file
with open(output_badusb_script, "w", encoding="ascii") as file:
    file.write("\n".join(badusb_script))

print(f"Conversion completed. The BadUSB Script file has been saved at: {output_badusb_script}")
