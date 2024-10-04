# Chirpy

This is a project to create a web server in Go based on the lessons on [Boot.dev](https://www.boot.dev/lessons/861ada77-c583-42c8-a265-657f2c453103).

## Description

Chirpy is a simple web server implemented in Go. It provides various endpoints to manage chirps and users, along with some administrative functionalities.

## Getting Started

### Prerequisites

- Go 1.19 or higher
- Environment variables `JWT_SECRET` and `POLKA_KEY` set in a `.env` file

### Installing

1. Clone the repository:

```sh
git clone https://github.com/AdeleRICHARD/chirpy.git
cd chirpy
```

2. Install dependencies:

```sh
go mod tidy
```

3. Create a `.env` file and set the required environment variables:

```sh
JWT_SECRET=your_jwt_secret
POLKA_KEY=your_polka_key
```

### Running the Server

To run the server, use the following command:

```sh
go run main.go
```

The server will start on port 8080.

### Debug Mode

To enable debug mode, use the `--debug` flag. This will delete the existing database file:

```sh
go run main.go --debug
```

## API Endpoints

The server provides the following endpoints:

- `GET /api/healthz` - Health check endpoint
- `POST /admin/reset` - Reset all users
- `POST /api/chirps` - Create a new chirp
- `GET /api/chirps` - Get all chirps
- `GET /api/chirps/{chirpID}` - Get a chirp by ID
- `DELETE /api/chirps/{chirpID}` - Delete a chirp by ID
- `POST /api/users` - Create a new user
- `POST /api/login` - User login
- `PUT /api/users` - Update user information
- `POST /api/refresh` - Refresh JWT token
- `POST /api/revoke` - Revoke JWT token
- `POST /api/polka/webhooks` - Handle Polka webhooks
- `/api/reset` - Custom reset handler

## License

This project does not have a license yet.

## Acknowledgments

- [Boot.dev](https://www.boot.dev/lessons/861ada77-c583-42c8-a265-657f2c453103) for the lessons on building a Go web server.

---

Feel free to modify the README.md file as needed.