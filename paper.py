# Import necessary libraries
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
import datetime

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
    if 'Submission Date' in df.columns:
        df['Submission Date'] = df['Submission Date'].astype(str)
    sheet = gc.open("Paper_Submissions").worksheet(worksheet_name)
    df = df.fillna('')
    df.replace([float('inf'), float('-inf')], '', inplace=True)
    sheet.update([df.columns.values.tolist()] + df.values.tolist())

# Load users from the "Users" worksheet
def load_users():
    user_data = load_data("Users")
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
    df = load_data("Users")
    df = pd.concat([df, new_user], ignore_index=True)
    save_data(df, "Users")

# Upload file to Google Drive and return the file ID
def upload_to_drive(file, filename, folder_id):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
        tmp_file.write(file.getvalue())
        tmp_file_path = tmp_file.name
    file_metadata = {"name": filename, "parents": [folder_id]}
    media = MediaFileUpload(tmp_file_path, resumable=True)
    try:
        file_response = drive_service.files().create(body=file_metadata, media_body=media, fields="id").execute()
        file_id = file_response.get("id")
        st.success("File uploaded successfully to Google Drive.")
        return file_id
    except Exception as e:
        st.error(f"Error during file upload: {e}")
    finally:
        os.remove(tmp_file_path)

# Main Streamlit App
st.sidebar.image("MOSHIP-1.png", use_column_width=True)
st.sidebar.title("Login / Register")

# Initialize session state for login
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "name" not in st.session_state:
    st.session_state["name"] = ""
if "role" not in st.session_state:
    st.session_state["role"] = ""

if not st.session_state["logged_in"]:
    option = st.sidebar.selectbox("Select an option", ["Login", "Register"])

    if option == "Login":
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        users = load_users()
        name, role = authenticate(username, password, users)

        if name:
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.session_state["name"] = name
            st.session_state["role"] = role
            st.sidebar.success(f"Welcome, {name}!")
        else:
            st.sidebar.error("Invalid username or password.")

    elif option == "Register":
        st.title("Register New User")
        new_username = st.text_input("Username")
        new_name = st.text_input("Name")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["author", "reviewer"])

        if st.button("Register"):
            register_user(new_username, new_name, new_password, new_role)
            st.success("User registered successfully!")

# Logout button
if st.session_state["logged_in"]:
	if st.sidebar.button("Logout"):
		st.session_state["logged_in"] = False
		st.session_state["username"] = ""
		st.session_state["name"] = ""
		st.session_state["role"] = ""
		st.sidebar.success("Logged out successfully.")
	name = st.session_state["name"]
	role = st.session_state["role"]

if role == "author":
	st.title("Author Dashboard")
	st.write("Submit and track your papers here.")
	# (Author dashboard code here)
	st.title("Author Dashboard")
	st.write("Submit and track your papers here.")
	
	# Paper Information Fields
	paper_title = st.text_input("Paper Title")
	paper_abstract = st.text_area("Abstract")
	paper_keywords = st.text_input("Keywords (comma-separated)")
	paper_file = st.file_uploader("Upload your paper (PDF or DOCX)", type=["pdf", "docx"], disabled=not all([paper_title, paper_abstract, paper_keywords]))

	if paper_file and all([paper_title, paper_abstract, paper_keywords]):
	    # Create a new author ID or fetch existing ID
	    author_id = username  # You can customize this as needed
	    folder_id = "1BzoASAVeCAWvJ5cX7c8plMSxpfTXvA8d"
	    submission_date = datetime.datetime.now().strftime("%Y-%m-%d")  # Get current date in YYYY-MM-DD format
    
	    paper_data = {
		"Author ID": author_id,
		"Author": name,
		"Title": paper_title,
		"Abstract": paper_abstract,
		"Keywords": paper_keywords,
		"Status": "Pending",
		"Reviewer": "",
		"Reviewer Comments": "",
		"File Name": paper_file.name,
		"Submission Date": submission_date  # Add submission date here
	    }
    
	    df = load_data("Submissions")  # Load from "Submissions" worksheet
	    df = pd.concat([df, pd.DataFrame([paper_data])], ignore_index=True)  # Update here
	    save_data(df, "Submissions")  # Save back to "Submissions" worksheet
	    file_id = upload_to_drive(paper_file, paper_file.name, folder_id)  # Call the updated upload function
		
	    if file_id:
		    # Save the file ID for the reviewer to access later
		    df.at[df.index[-1], "File ID"] = file_id  # Store the file ID in the DataFrame
		    save_data(df, "Submissions")  # Update the Submissions sheet with the new file ID
		    st.success("Paper submitted successfully!")
	
	
elif role == "reviewer":
	st.title("Reviewer Dashboard")
        st.write("View and review assigned papers.")
        # (Reviewer dashboard code here)
	        df = load_data("Submissions")  # Load from "Submissions" worksheet
        assigned_papers = df[(df["Status"] == "Pending") & (df["Reviewer"] == username)]
        st.write(assigned_papers)
        
        if not assigned_papers.empty:
            paper_id = st.selectbox("Select a paper to review", assigned_papers.index)
            st.write("Paper Name:", assigned_papers.loc[paper_id, "File Name"])
            
            # Create a clickable link to the file
            file_id = assigned_papers.loc[paper_id, "File ID"]
            if file_id:
                file_url = f"https://drive.google.com/file/d/{file_id}/view"
                st.write("View Paper: [Click here](%s)" % file_url)  # Create a clickable link

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
	st.title("MOSHIP Admin Dashboard")
        st.write("Manage papers, assign reviewers, and delete papers.")
        # (Admin dashboard code here)
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

st.sidebar.markdown("---")
st.sidebar.markdown("Developed by Universiti Teknologi PETRONAS<sup>TM</sup>", unsafe_allow_html=True)
