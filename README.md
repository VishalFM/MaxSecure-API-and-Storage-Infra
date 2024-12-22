# Redis and Malware Routes API

This repository contains the implementation of API endpoints for interacting with Redis cache and handling various malware-related functionalities such as URL searches and file management. It uses Flask as the web framework and integrates with Redis, PostgreSQL, and other services for malicious URL checks, file type validation, and spyware signature management.

## Project Overview

This project provides APIs to:
- Search for MD5 signatures in cache and return related results.
- Check malicious URLs using different sources such as RL API, VT API.
- Insert and manage various data like file types, spyware categories, spyware names, signatures, and white file names.

## Installation

Follow the steps below to set up the project locally:

### Prerequisites

- Python 3.x
- Redis server (locally or remotely hosted)
- PostgreSQL (for handling signatures and related data)

### Steps

1. Clone the repository:

   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```

2. Create a virtual environment and activate it:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up the environment variables for your configuration (e.g., Redis connection, database credentials, API keys). You can use a `.env` file or configure them directly in your environment.

5. Run the application:

   ```bash
   python run.py
   ```

6. The API will be available at `http://127.0.0.1:5000`.

## API Endpoints

### Search API
- **GET** `/search/<md5_signature>`  
  Search for a given MD5 signature in the Redis cache (malware and white caches).

- **GET** `/searchMaliciousUrl`  
  Search for a URL (base64 encoded or plain) in the malicious URL cache and check if it has a high score in RL or VT APIs.

### Malware Routes
- **POST** `/file-types`  
  Insert file types into the database.

- **POST** `/source`  
  Insert source information into the database.

- **POST** `/spyware-category`  
  Insert spyware category records into the database.

- **POST** `/spyware-name`  
  Insert spyware name records with categories.

- **POST** `/signatures/signatures`  
  Bulk insert spyware signatures.

- **DELETE** `/signatures/signatures/<signature>`  
  Delete a spyware signature by its identifier.

- **PUT** `/signatures/signatures/<signature>`  
  Update a spyware signature's details.

- **GET** `/signatures/search_signatures`  
  Search for signatures based on various filters like date, OS, and entry status.

- **POST** `/whitefilenames`  
  Bulk insert white file names into the database.

- **POST** `/hits`  
  Bulk insert hit data into the database.

- **POST** `/upload-signatures`  
  Upload and insert signatures from a CSV file.

## Services

### RL_VT_API_services
- Provides methods for interacting with the RL and VT APIs to check URLs for malicious scores.

### malicious_urls_services
- Contains methods to insert and check for malicious URLs in the Redis cache.

### redis_services
- Provides a service to interact with Redis for searching and caching malicious data.

### file_type_services
- Validates and inserts file types into the database.

### signature_services
- Handles the bulk insertion, deletion, and update of spyware signatures.

Make sure the application is running and Redis/PostgreSQL servers are configured before testing.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit them (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Redis for caching and quick lookups.
- Flask for building the web API.
- PostgreSQL for managing the signature, Malicious URLs and related data.
- VT and RL for their malicious URL checking services.
