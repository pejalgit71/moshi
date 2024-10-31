import streamlit as st
import streamlit_authenticator as stauth
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import bcrypt
import os
import tempfile
import matplotlib.pyplot as plt

# Google Sheets and Drive API setup
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]

# Load credentials from Streamlit secrets
credentials = Credentials.from_service_account_info(
    {
        "type": st.secrets["gcp_service_account"]["type"],
        "project_id": st.secrets["gcp_service_account"]["project_id"],
        "private_key_id": st.secrets["gcp_service_account"]["private_key_id"],
        "private_key": st.secrets["gcp_service_account"]["private_key"].replace("\\n", "\n"),
        "client_email": st.secrets["gcp_service_account"]["client_email"],
        "client_id": st.secrets["gcp_service_account"]["client_id"],
        "auth_uri": st.secrets["gcp_service_account"]["auth_uri"],
        "token_uri": st.secrets["gcp_service_account"]["token_uri"],
        "auth_provider_x509_cert_url": st.secrets["gcp_service_account"]["auth_provider_x509_cert_url"],
        "client_x509_cert_url": st.secrets["gcp_service_account"]["client_x509_cert_url"]
    },
    scopes=SCOPES
)

gc = gspread.authorize(credentials)

# Drive service
drive_service = build("drive", "v3", credentials=credentials)

# Load data from a specific worksheet
def load_data(worksheet_name):
    sheet = gc.open("Paper_Submissions").worksheet(worksheet_name)
    data = pd.DataFrame(sheet.get_all_records())
    return data

# Save DataFrame back to a specific worksheet
def save_data(df, worksheet_name):
    sheet = gc.open("Paper_Submissions").worksheet(worksheet_name)
    df = df.fillna('')
    df.replace([float('inf'), float('-inf')], '', inplace=True)
    sheet.update([df.columns.values.tolist()] + df.values.tolist())

# Load users from the "Users" worksheet
def load_users():
    user_data = load_data("Users")  # Load from "Users" worksheet
    users = {
        "usernames": {
            row["Username"]: {
                "name": row["Name"],
                "password": row["Password"],
                "role": row["Role"]
            }
            for _, row in user_data.iterrows()
        }
    }
    return users

# Authenticate user using bcrypt hashed passwords
def authenticate(username, password, users):
    user = users["usernames"].get(username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
        return user["name"], user["role"]
    return None, None

# Register a new user
def register_user(username, name, password, role):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = pd.DataFrame([{
        "Username": username,
        "Name": name,
        "Password": hashed_password,
        "Role": role
    }])
    
    df = load_data("Users")  # Load from "Users" worksheet
    df = pd.concat([df, new_user], ignore_index=True)
    
    save_data(df, "Users")  # Save back to "Users" worksheet


# Upload file to Google Drive
def upload_to_drive(file, filename):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
        tmp_file.write(file.getvalue())
        tmp_file_path = tmp_file.name

    file_metadata = {"name": filename, "parents": [os.getenv("1BzoASAVeCAWvJ5cX7c8plMSxpfTXvA8d")]}
    media = MediaFileUpload(tmp_file_path, resumable=True)
    drive_service.files().create(body=file_metadata, media_body=media, fields="id").execute()
    os.remove(tmp_file_path)

# Main Streamlit App
st.sidebar.title("Login / Register")
option = st.sidebar.selectbox("Select an option", ["Login", "Register"])

if option == "Login":
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    users = load_users()
    name, role = authenticate(username, password, users)

    if name:
        st.sidebar.success(f"Welcome, {name}!")

        if role == "author":
            st.title("Author Dashboard")
            st.write("Submit and track your papers here.")
            
            paper_title = st.text_input("Paper Title")
            paper_abstract = st.text_area("Abstract")
            paper_keywords = st.text_input("Keywords (comma-separated)")
            paper_file = st.file_uploader("Upload your paper (PDF or DOCX)", type=["pdf", "docx"], disabled=not all([paper_title, paper_abstract, paper_keywords]))
# ----------------
            
            if paper_file and all([paper_title, paper_abstract, paper_keywords]):
                # Create a new author ID or fetch existing ID
                author_id = username  # You can customize this as needed
                paper_data = {
                    "Author ID": author_id,
                    "Author": name,
                    "Title": paper_title,
                    "Abstract": paper_abstract,
                    "Keywords": paper_keywords,
                    "Status": "Pending",
                    "Reviewer": "",
                    "Reviewer Comments": "",
                    "File Name": paper_file.name
                }
                df = load_data("Submissions")  # Load from "Submissions" worksheet
                df = pd.concat([df, pd.DataFrame([paper_data])], ignore_index=True)  # Update here
                save_data(df, "Submissions")  # Save back to "Submissions" worksheet
                upload_to_drive(paper_file, paper_file.name)  # Call the updated upload function
                st.success("Paper submitted successfully!")

# ------
        elif role == "reviewer":
            st.title("Reviewer Dashboard")
            st.write("View and review assigned papers.")
            
            df = load_data("Submissions")  # Load from "Submissions" worksheet
            assigned_papers = df[(df["Status"] == "Pending") & (df["Reviewer"] == username)]
            st.write(assigned_papers)
            
            if not assigned_papers.empty:
                paper_id = st.selectbox("Select a paper to review", assigned_papers.index)
                st.write("Paper Name:", assigned_papers.loc[paper_id, "File Name"])
                
                review_status = st.radio("Mark paper as:", ["Accepted", "Not Accepted"])
                review_comments = st.text_area("Provide comments:")
                
                if st.button("Submit Review"):
                    df.at[paper_id, "Status"] = review_status
                    df.at[paper_id, "Reviewer Comments"] = review_comments
                    save_data(df, "Submissions")  # Save back to "Submissions" worksheet
                    st.success("Review submitted successfully!")
            else:
                st.write("No papers assigned for review.")

    
        
        elif role == "admin":
            st.title("Admin Dashboard")
            st.write("Manage papers, assign reviewers, and delete papers.")
            
            df = load_data("Submissions")
            df.index = range(1, len(df) + 1)
            st.write(df)
            
            # Filter for reviewed and pending papers
            reviewed_papers = df[df["Status"] != "Pending"]
            pending_papers = df[df["Status"] == "Pending"]
        
            # Display Pie Chart of Reviewed vs Pending
            with st.expander("Review Status Summary"):
                review_counts = df["Status"].value_counts()
                fig, ax = plt.subplots()
                ax.pie(review_counts, labels=review_counts.index, autopct='%1.1f%%', startangle=90)
                ax.axis("equal")  # Equal aspect ratio ensures the pie chart is circular.
                st.pyplot(fig)
            
            # Display Line Chart of Reviewed Papers Over Time (if you have a 'Submission Date' column)
            if "Submission Date" in df.columns:
                with st.expander("Reviewed Papers Over Time"):
                    df["Submission Date"] = pd.to_datetime(df["Submission Date"])
                    reviewed_over_time = reviewed_papers.groupby("Submission Date").size().cumsum()
                    st.line_chart(reviewed_over_time)
        
            # Assign Reviewer
            unassigned_papers = df[(df["Status"] == "Pending") & (df["Reviewer"] == "")]
            if not unassigned_papers.empty:
                paper_to_assign = st.selectbox("Select a paper to assign a reviewer", unassigned_papers.index)
                reviewer = st.selectbox("Select a reviewer", [u for u in users["usernames"] if users["usernames"][u]["role"] == "reviewer"])
                if st.button("Assign Reviewer"):
                    df.at[paper_to_assign, "Reviewer"] = reviewer
                    save_data(df, "Submissions")
                    st.success("Reviewer assigned successfully!")
            
            # Delete Paper
            with st.expander("Delete Paper"):
                paper_to_delete = st.selectbox("Select a paper to delete", df["File Name"])
                if st.button("Delete Paper"):
                    df = df[df["File Name"] != paper_to_delete]
                    save_data(df, "Submissions")
                    st.success("Paper deleted successfully!")
                    
    else:
        st.sidebar.error("Incorrect username/password.")

elif option == "Register":
    new_username = st.text_input("Choose a Username")
    new_name = st.text_input("Your Name")
    new_password = st.text_input("Choose a Password", type="password")
    role = st.selectbox("Select Role", ["author", "reviewer", "admin"])

    if st.button("Register"):
        if new_username and new_name and new_password:
            # Check if the username already exists
            users = load_users()
            if new_username in users["usernames"]:
                st.error("Username already exists. Please choose another.")
            else:
                register_user(new_username, new_name, new_password, role)
                st.success("Registration successful! You can now log in.")
        else:
            st.error("Please fill in all fields.")
