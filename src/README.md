# Mergington High School Activities API

A simple FastAPI application that lets visitors view activities and participants, while assigned teachers manage registrations.

## Features

- View activities and current participants without signing in
- Sign up and unregister students as an authenticated teacher
- Teacher credentials stored locally as salted password hashes

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Run the application:

   ```
   cp src/teachers.example.json src/teachers.json
   python -m src.manage_teachers staff
   SESSION_SECRET="$(openssl rand -hex 32)" uvicorn src.app:app --reload
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                               | Description                                                          |
| ------ | ---------------------------------------------------------------------- | -------------------------------------------------------------------- |
| GET    | `/activities`                                                          | Get activities and current participant counts                       |
| GET    | `/auth/session`                                                        | Check whether the visitor is signed in as a teacher                  |
| POST   | `/auth/login`                                                          | Sign in with an assigned teacher username and password               |
| POST   | `/auth/logout`                                                         | Sign out                                                              |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu`      | Teacher-only registration                                             |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu`  | Teacher-only unregistration                                           |

The credential file is local and ignored by Git; it stores salted PBKDF2 password hashes rather than plaintext passwords. Use `python -m src.manage_teachers <username>` to assign a teacher password. Set a persistent `SESSION_SECRET` in deployment; if it is omitted, a temporary random secret is generated and all sessions expire when the server restarts. Do not expose the development server directly to the internet.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

Activity data is stored in memory and resets when the server restarts. Teacher credentials are stored in `src/teachers.json`.
