import os
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import logging
import openai
from dotenv import load_dotenv
from tabulate import tabulate

# Load environment variables from the .env file
load_dotenv()

# Initialize OpenAI client with the API key
api_key = os.getenv("OPENAI_API_KEY")
if api_key is None:
    st.error("OpenAI API key not found. Please check your .env file.")
else:
    openai.api_key = api_key

# Load CSV file from the same directory as this Python script
csv_file_path = os.path.join(os.path.dirname(__file__), "csv_file.csv")
df = pd.read_csv(csv_file_path)

# Custom preprocessing for transaction data
def preprocess_data(data):
    if "transaction_id" in data.columns and "user_id.1" in data.columns:
        data = data.drop(columns=["transaction_id", "user_id.1"])
    data.sort_values(by=["user_id", "timestamp"], ascending=[True, False], inplace=True)
    data.reset_index(drop=True, inplace=True)
    return data


# Set a custom title, layout, and icon for the app
st.set_page_config(
    page_title="Bank Fraudulence Checker",
    layout="wide",
    page_icon="🏦"
)


# Simulate Okta login (to be replaced with real Okta or secure authentication)
def okta_login():
    st.title("🏦 Bank Fraudulence Checker Login", anchor="login")
    st.markdown(
        "<style>div.stButton > button {background-color: #0a9396; color: white;}</style>",
        unsafe_allow_html=True
    )
    username = st.text_input("Username", placeholder="Enter your username")
    password = st.text_input("Password", type="password", placeholder="Enter your password")

    if st.button("Login"):
        # Simulated secure login credentials
        if username == "Edima" and password == "Opeyemi":
            st.session_state['logged_in'] = True
            st.success("Welcome to your secure dashboard! 🎉")
        else:
            st.error("Access Denied: Invalid login credentials.")


# Display user information and transactions
def display_user_info():
    st.title("📊 User Transaction Records", anchor="records")

    user_input = st.text_input("Enter User ID", placeholder="User ID (numeric)")

    if user_input:
        try:
            user_id = int(user_input)
            specific_user = df[df["user_id"] == user_id]

            if 'show_records' not in st.session_state:
                st.session_state['show_records'] = False

            if st.button("Show Records", key='show_records_button'):
                st.session_state['show_records'] = True

            if st.session_state['show_records']:
                if specific_user.empty:
                    st.warning(f"No transactions found for User ID: {user_id}")
                else:
                    specific_user.sort_values(by=["timestamp"], ascending=[False], inplace=True)
                    specific_user.reset_index(drop=True, inplace=True)

                    st.text("Transaction Records:")
                    st.dataframe(specific_user)
                    visualize_transactions(specific_user)
                    geolocation_risk(specific_user)
                    fraud_trends(specific_user)

        except ValueError:
            st.error("Please enter a valid User ID (numeric).")


# Analyze fraud trends
def fraud_trends(specific_user):
    st.markdown("### 🛑 Fraud Detection and Analysis")
    avg_for_past_month = specific_user["amount"].iloc[1:31].mean()

    # Add transaction type factor
    transaction_type = specific_user['transaction_type'].iloc[0]
    if transaction_type == "withdrawal":
        threshold = avg_for_past_month * 2
    elif transaction_type == "transfer":
        threshold = avg_for_past_month * 1.7
    else:
        threshold = avg_for_past_month * 1.5

    # Check for fraud
    if specific_user["amount"].iloc[0] > threshold:
        st.error(f"⚠️ Alert: High Possibility of Fraud Detected for {transaction_type}")
    else:
        st.warning("Low Possibility of Fraud")

    # Call OpenAI API for fraud trends analysis and advice
    try:
        prompt = (f"Analyze records for unusual transactions, flags abnormal patterns "
                  f"(e.g., large transfer from unknown location), and suggest action.\n"
                  f"{specific_user.to_dict(orient='records')}")

        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": prompt}]
        )

        advice = response['choices'][0]['message']['content']
        st.markdown("#### 🔍Fraud Analysis:")
        st.write(advice)
        st.success("Notification sent to fraud detection team.")

    except Exception as e:
        st.error(f"Error communicating with OpenAI API: {e}")


# Get specific user transactions
def get_user_transactions(user_id, data):
    specific_user = data[data["user_id"] == user_id]
    specific_user.sort_values(by=["timestamp"], ascending=[False], inplace=True)
    specific_user.reset_index(drop=True, inplace=True)

    if specific_user.empty:
        st.text(f"No transactions found for User ID: {user_id}")
    else:
        st.text(tabulate(specific_user, headers="keys", tablefmt="grid"))
        return specific_user


# Upload new data and recompute
def load_and_assess_new_data():
    st.title("📁 Upload and Assess New Data")

    uploaded_file = st.file_uploader("Upload a new CSV file", type="csv")

    if uploaded_file is not None:
        new_data = pd.read_csv(uploaded_file, on_bad_lines='skip')
        new_data = new_data.drop(columns=["transaction_id", "user_id.1"])

        global df
        df = pd.concat([df, new_data], ignore_index=True)
        df = preprocess_data(df)

        st.success("✅ New data loaded and merged successfully!")


# Visualize transaction history
def visualize_transactions(user_data):
    st.markdown("### 📈 User Transaction History")
    plt.figure(figsize=(12, 6))
    sns.lineplot(x='timestamp', y='amount', data=user_data, marker='o', color="red", linewidth=2.5)  # Changed color to red

    plt.xticks(rotation=45, ha='right')
    plt.title("📊 Transaction History", fontsize=16, color="blue")
    plt.xlabel("Timestamp", fontsize=12)
    plt.ylabel("Transaction Amount (USD)", fontsize=12)
    plt.grid(True, linestyle='--', linewidth=0.5)

    plt.legend(["Transaction Amount"], loc="upper left")
    plt.tight_layout()

    st.pyplot(plt)


# Assess geolocation risks
def geolocation_risk(user_data):
    st.markdown("### 🌍 Geolocation Risk Assessment")

    high_risk_locations = ['Tokyo', 'Paris']
    location = user_data['location'].iloc[0]

    if location in high_risk_locations:
        st.error(f"⚠️ Transaction from {location} - **High-Risk Location**")
        st.markdown(
            f"<p style='color:red;'>🌍 Transactions from {location} are considered high-risk due to unusual activity.</p>",
            unsafe_allow_html=True
        )
    else:
        st.success(f"✅ Transaction from {location} - **Normal Location**")
        st.markdown(
            f"<p style='color:green;'>🌍 No unusual activity detected for transactions from {location}. Location is safe.</p>",
            unsafe_allow_html=True
        )


# Main App Logic
def main():
    st.sidebar.title("🗂️ Navigation")

    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if not st.session_state['logged_in']:
        okta_login()
    else:
        page = st.sidebar.radio("Navigate", ["Transaction Records", "Upload CSV", "Logout"])

        if page == "Transaction Records":
            display_user_info()
        elif page == "Upload CSV":
            load_and_assess_new_data()
        elif page == "Logout":
            st.session_state['logged_in'] = False
            st.success("You have successfully logged out.")
            st.experimental_rerun()


if __name__ == "__main__":
    main()
