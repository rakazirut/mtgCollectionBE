# Magic the Gathering Collection - Backend

[![mtgCollectionBE](https://github.com/rakazirut/mtgCollectionBE/actions/workflows/fly.yml/badge.svg)](https://github.com/rakazirut/mtgCollectionBE/actions/workflows/fly.yml)

## Description
This application works in parallel with [Magic the Gathering Collection - Frontend](https://github.com/slandath/mtgCollectionFE) to provide users a place to create, maintain, and otherwise view their magic card collections as well as the current market value for cards in their collection in USD.

We've leveraged technologies such as [express.js](https://expressjs.com/), [node.js](https://nodejs.org/en/), [postgresql](https://www.postgresql.org/), [docker](https://www.docker.com/), and [playwright](https://playwright.dev/) to accomplish our goal of creating and testing an API and database combination to support the needs of the Frontend application.

## How to run the project

1. Clone the repository
2. Use NPM to install dependancies
    -  `npm i`
3. Create `.env` file at the root level of the project
    - Example
        ```
        PORT = 3000
        DB_PASSWORD = db_password
        JWT_SECRET_KEY = your_secret_key
        API_TOKEN = test_api_token
        USER = test_username
        PASSWORD = test_password
        ACCOUNTID = test_account_id
        ```
4. Two options:
    - Use command `npm start` to run the application 
    - OR use Docker related files to create a container for the project to run in isolation 
        - requires Docker to be installed on the local machine
            1. `docker compose build`
            2. `docker compose up`

## Running Tests
This project utilizes playwright for handling api tests. Simply use command `npx playwright test` to run all test specs or you can specify a spec file to run for example `npx playwright test ./tests/login.spec.ts` to run all login api tests.

---
## Credits
Application code written by [Tom Slanda](https://github.com/slandath) and [Rob Kazirut](https://github.com/rakazirut) with help from the following:

- [Scryfall](https://scryfall.com/) - Providing up to date card prices

- [Geeks for Geeks](https://www.geeksforgeeks.org/jwt-authentication-with-node-js/) - JWT Authentication guide

- [Playwright](https://playwright.dev/docs/intro) - Playwright documentation