import csv
import os
import requests
import hashlib
import re

credintials_file = 'users.csv'

def initialize_user_data_file():
    if not os.path.exists(credintials_file):
        with open(credintials_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['email', 'password', 'question', 'answer'])


# using hashlib to encrypt password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def user_exists(email):
    with open(credintials_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header
        for row in reader:
            if row[0] == email:
                return True
    return False


def validate_password(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    return True, ""


def validate_email(email):
    if '@' not in email:
        return False, "Invalid email address."
    return True, ""


def register_user():
    email = input("Enter email: ")
    is_valid, message = validate_email(email)
    if not is_valid:
        print(message)
        return

    if user_exists(email):
        print("Email already exists. Please choose a different email.")
        return
    
    password = input("Enter password: ")
    is_valid, message = validate_password(password)
    if not is_valid:
        print(message)
        return
    
    question = input("Enter a personal question for password recovery: ")
    answer = input("Enter the answer to your personal question: ")
    
    hashed_password = hash_password(password)
    hashed_answer = hash_password(answer)
    
    with open(credintials_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, hashed_password, question, hashed_answer])
    
    print("User registered successfully!")


# Function to authenticate a user
def authenticate_user():
    email = input("Enter email: ")
    password = input("Enter password: ")
    hashed_password = hash_password(password)
    
    with open(credintials_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if row[0] == email and row[1] == hashed_password:
                print("Authentication successful!")
                return True
    print("Authentication failed!")
    return False


def reset_password():
    email = input("Enter your email: ")
    if not user_exists(email):
        print("Email does not exist.")
        return
    
    with open(credintials_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header
        for row in reader:
            if row[0] == email:
                question = row[2]
                print(f"Answer the following question to reset your password: {question}")
                answer = input("Your answer: ")
                hashed_answer = hash_password(answer)
                if hashed_answer == row[3]:
                    new_password = input("Enter new password: ")
                    is_valid, message = validate_password(new_password)
                    if not is_valid:
                        print(message)
                        return
                    hashed_new_password = hash_password(new_password)
                    row[1] = hashed_new_password
                    update_user_data(email, row)
                    print("Password reset successfully!")
                    return
                else:
                    print("Incorrect answer.")
                    return


def update_user_data(email, updated_row):
    rows = []
    with open(credintials_file, mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)
    
    with open(credintials_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        for row in rows:
            if row[0] == email:
                writer.writerow(updated_row)
            else:
                writer.writerow(row)


def before_login_menu():
    print("1. Register User")
    print("2. Login")
    print("3. Forget Password")
    print("4. Exit")

#api works
def after_login_menu():
    print("1. Search Books by title")
    print("2. Search Authors's work")
    print("3. Search Works by Subject")
    print("4. Logout")


# featch books with matching title

def fetch_book_titles(query):
    # Using the search endpoint
    url = f"https://openlibrary.org/search.json?q={query}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        books = data.get('docs', [])
        
        titles = [book['title'] for book in books if 'title' in book]
        return titles
    else:
        return []


# featch work of authors byt here name

def fetch_author_names(query):
    # Using the search authors endpoint
    url = f"https://openlibrary.org/search/authors.json?q={query}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        authors = data.get('docs', [])
        
        author_names = [author['name'] for author in authors if 'name' in author]
        return author_names
    else:
        return []


# search books by subject like {drama, horror,crime, history etc}

def fetch_works_by_subject(subject):
    url = f"https://openlibrary.org/subjects/{subject}.json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        works = data.get('works', [])
        
        work_titles = [work['title'] for work in works if 'title' in work]
        return work_titles
    else:
        return []


# main function
def main():
    initialize_user_data_file()
    authenticated = False
    
    while True:
        if not authenticated:
            before_login_menu()
            choice = input("Enter your choice: ")
            
            if choice == '1':
                register_user()
            elif choice == '2':
                authenticated = authenticate_user()
            elif choice == '3':
                reset_password()
            elif choice == '4':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            after_login_menu()
            choice = input("Enter your choice: ")
            
            if choice == '1':
                query = input("Enter book search query: ")
                titles = fetch_book_titles(query)
                if titles:
                    print("Book Titles Found:")
                    for title in titles:
                        print(title)
                else:
                    print("No books found.")
            elif choice == '2':
                query = input("Enter author search query: ")
                author_names = fetch_author_names(query)
                if author_names:
                    print("Authors Found:")
                    for name in author_names:
                        print(name)
                else:
                    print("No authors found.")
            elif choice == '3':
                subject = input("Enter subject: ")
                works = fetch_works_by_subject(subject)
                if works:
                    print("Works Found:")
                    for work in works:
                        print(work)
                else:
                    print("No works found.")
            elif choice == '4':
                print("Logging out...")
                authenticated = False
            else:
                print("Invalid choice. Please try again.")

main()
