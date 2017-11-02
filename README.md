# BRAG Web Application
**By: Faza Fahleraz**

## Project Description
BRAG is a web application where you can post your belongings so that everyone
can see it. You can browse all items according to their category. You can also
edit and delete items (but of course you have to be logged in as that user).
Enjoy.


## Setup and Running the App Locally
### Running the VM
- Navigate to the 'vagrant' folder inside the project
_ Run: vagrant up
- Run: vagrant ssh

### Prepare the database
- Change directory to the 'catalog' folder inside 'vagrant'
- Run: python3 database_setup.py

### Run the App
- Run: python3 application.py


## Loggin In
Currently this web app only supports login with Google.

## API Endpoints
There are two API endpoints for this app:
- Category list: sending a GET request to localhost:8000/api/categories/ will
retrurn a list of all categories in JSON.
- Items in a category: sending a GET request to
localhost:8000/api/category/<category_name>/ will return a list of all items
in a category in JSON.
# Brag: A Catalog Web App
