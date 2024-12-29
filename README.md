To build and run the Docker container:

docker build -t detect_obfuscated_code .

Run the Docker container: Once the image is built, you can run the container:

docker run -it detect_obfuscated_code

Customizations and Enhancements:

1.Replace your_api_key with a valid API key from VirusTotal to use the VirusTotal integration.

2.Modify the script to accept input from a file or user input for different obfuscated code samples.

To run from terminal simply install dependencies, download the script, make it executable then run it.
