#!/usr/bin/env python3
"""
Create comprehensive DLP test databases in Excel and text formats
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os
import json
import csv

# Create databases directory
os.makedirs('databases', exist_ok=True)
os.makedirs('databases/excel', exist_ok=True)
os.makedirs('databases/text', exist_ok=True)
os.makedirs('databases/csv', exist_ok=True)
os.makedirs('databases/configs', exist_ok=True)
os.makedirs('databases/logs', exist_ok=True)

print("📁 Creating comprehensive DLP test databases...")

# ============================================================================
# DATABASE 1: EMPLOYEE MASTER DATABASE (With PII)
# ============================================================================
print("\n1. Creating Employee Master Database...")

# Generate realistic employee data
departments = ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance', 'IT', 'Operations', 'Customer Support']
positions = ['Manager', 'Senior', 'Junior', 'Director', 'VP', 'Associate', 'Analyst', 'Specialist']

employees = []
for i in range(1, 51):
    emp_id = 1000 + i
    first_name = random.choice(['John', 'Jane', 'Robert', 'Mary', 'Michael', 'Sarah', 'David', 'Lisa', 'James', 'Jennifer'])
    last_name = random.choice(['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez'])
    
    employees.append({
        'Employee_ID': emp_id,
        'First_Name': first_name,
        'Last_Name': last_name,
        'Full_Name': f'{first_name} {last_name}',
        'Email': f'{first_name.lower()}.{last_name.lower()}@company.com',
        'Phone': f'({random.randint(200,999)}) {random.randint(100,999)}-{random.randint(1000,9999)}',
        'SSN': f'{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}',
        'Date_of_Birth': f'{random.randint(1960,2000)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'Department': random.choice(departments),
        'Position': random.choice(positions),
        'Salary': random.randint(50000, 150000),
        'Hire_Date': f'{random.randint(2015,2023)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'Address': f'{random.randint(100,9999)} {random.choice(["Main", "Oak", "Maple", "Pine"])} St',
        'City': random.choice(['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix']),
        'State': random.choice(['NY', 'CA', 'IL', 'TX', 'AZ']),
        'Zip_Code': f'{random.randint(10000, 99999)}',
        'Emergency_Contact': f'({random.randint(200,999)}) {random.randint(100,999)}-{random.randint(1000,9999)}',
        'Emergency_Name': random.choice(['Spouse', 'Parent', 'Sibling']),
        'Bank_Account': f'{random.randint(1000000000, 9999999999)}'  # ADDED THIS LINE
    })

df_employees = pd.DataFrame(employees)

# Save to Excel
employee_excel = 'databases/excel/Employee_Master_Database.xlsx'
with pd.ExcelWriter(employee_excel, engine='openpyxl') as writer:
    df_employees.to_excel(writer, sheet_name='Employees', index=False)
    
    # Add a sheet with sensitive payroll info
    payroll_data = df_employees[['Employee_ID', 'Full_Name', 'Salary', 'Bank_Account']].copy()
    payroll_data['Routing_Number'] = [f'{random.randint(100000000, 999999999)}' for _ in range(len(df_employees))]
    payroll_data.to_excel(writer, sheet_name='Payroll_Info', index=False)

print(f"   ✅ Created: {employee_excel}")

# ============================================================================
# DATABASE 2: CUSTOMER DATABASE (With Payment Info)
# ============================================================================
print("\n2. Creating Customer Database with Payment Information...")

customers = []
credit_card_types = ['Visa', 'MasterCard', 'American Express', 'Discover']
credit_card_prefixes = {
    'Visa': '4',
    'MasterCard': '5',
    'American Express': '3',
    'Discover': '6'
}

for i in range(1, 101):
    cust_id = 5000 + i
    first = random.choice(['Alex', 'Taylor', 'Jordan', 'Casey', 'Morgan', 'Riley', 'Dakota', 'Quinn'])
    last = random.choice(['Anderson', 'Thomas', 'Jackson', 'White', 'Harris', 'Martin', 'Thompson', 'Garcia'])
    card_type = random.choice(credit_card_types)
    
    # Generate realistic credit card number
    if card_type == 'American Express':
        card_num = f'3{random.randint(4,7)}{random.randint(10000000000000, 99999999999999):014d}'
    else:
        prefix = credit_card_prefixes[card_type]
        card_num = prefix + f'{random.randint(100000000000000, 999999999999999):015d}'
    
    customers.append({
        'Customer_ID': cust_id,
        'First_Name': first,
        'Last_Name': last,
        'Email': f'{first.lower()}.{last.lower()}@gmail.com',
        'Phone': f'+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}',
        'Credit_Card_Type': card_type,
        'Credit_Card_Number': card_num,
        'Credit_Card_Expiry': f'{random.randint(1,12):02d}/{random.randint(24,30)}',
        'Credit_Card_CVV': f'{random.randint(100,999)}',
        'Billing_Address': f'{random.randint(100,9999)} {random.choice(["Park", "Lake", "Hill", "River"])} Ave',
        'Billing_City': random.choice(['New York', 'Los Angeles', 'Chicago', 'Miami', 'Seattle']),
        'Billing_State': random.choice(['NY', 'CA', 'IL', 'FL', 'WA']),
        'Billing_ZIP': f'{random.randint(10000, 99999)}',
        'Last_Purchase_Date': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'Total_Spent': round(random.uniform(100, 10000), 2),
        'Customer_Since': f'{random.randint(2018,2023)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
    })

df_customers = pd.DataFrame(customers)

# Save to Excel
customer_excel = 'databases/excel/Customer_Database.xlsx'
with pd.ExcelWriter(customer_excel, engine='openpyxl') as writer:
    df_customers.to_excel(writer, sheet_name='Customers', index=False)
    
    # Add transaction history sheet
    transactions = []
    for cust in customers[:20]:  # Add transactions for first 20 customers
        for _ in range(random.randint(1, 5)):
            transactions.append({
                'Transaction_ID': f'TXN{random.randint(100000, 999999)}',
                'Customer_ID': cust['Customer_ID'],
                'Customer_Name': f"{cust['First_Name']} {cust['Last_Name']}",
                'Credit_Card_Last4': cust['Credit_Card_Number'][-4:],
                'Amount': round(random.uniform(10, 500), 2),
                'Date': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
                'Merchant': random.choice(['Amazon', 'Walmart', 'Target', 'Best Buy', 'Starbucks']),
                'Status': random.choice(['Completed', 'Pending', 'Refunded'])
            })
    
    df_transactions = pd.DataFrame(transactions)
    df_transactions.to_excel(writer, sheet_name='Transactions', index=False)

print(f"   ✅ Created: {customer_excel}")

# ============================================================================
# DATABASE 3: HEALTHCARE PATIENT RECORDS (Highly Sensitive)
# ============================================================================
print("\n3. Creating Healthcare Patient Records...")

medical_conditions = ['Hypertension', 'Diabetes', 'Asthma', 'Arthritis', 'Migraine', 'Anxiety', 'Depression']
medications = ['Lisinopril', 'Metformin', 'Albuterol', 'Ibuprofen', 'Sumatriptan', 'Sertraline', 'Atorvastatin']

patients = []
for i in range(1, 31):
    patient_id = f'PT{1000 + i:04d}'
    first = random.choice(['James', 'Patricia', 'Robert', 'Linda', 'William', 'Elizabeth', 'David', 'Susan'])
    last = random.choice(['Wilson', 'Moore', 'Taylor', 'Anderson', 'Thomas', 'Jackson', 'White', 'Harris'])
    
    patients.append({
        'Patient_ID': patient_id,
        'First_Name': first,
        'Last_Name': last,
        'Date_of_Birth': f'{random.randint(1940,2000)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'SSN': f'{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}',
        'Address': f'{random.randint(100,9999)} {random.choice(["Medical", "Health", "Care", "Wellness"])} Dr',
        'Phone': f'{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}',
        'Email': f'patient.{first.lower()}.{last.lower()}@healthcare.org',
        'Emergency_Contact': f'{random.choice(["Spouse", "Child", "Parent"])}: ({random.randint(200,999)}) {random.randint(100,999)}-{random.randint(1000,9999)}',
        'Primary_Condition': random.choice(medical_conditions),
        'Medication': random.choice(medications),
        'Last_Visit': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'Next_Appointment': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'Insurance_ID': f'INS{random.randint(100000, 999999)}',
        'Insurance_Provider': random.choice(['BlueCross', 'Aetna', 'UnitedHealth', 'Cigna', 'Humana']),
        'Doctor_Notes': f'Patient presents with {random.choice(["mild", "moderate", "severe"])} symptoms. Follow up in {random.randint(1,6)} months.'
    })

df_patients = pd.DataFrame(patients)

# Save to Excel
healthcare_excel = 'databases/excel/Healthcare_Records.xlsx'
df_patients.to_excel(healthcare_excel, index=False)
print(f"   ✅ Created: {healthcare_excel}")

# ============================================================================
# DATABASE 4: FINANCIAL TRANSACTIONS DATABASE
# ============================================================================
print("\n4. Creating Financial Transactions Database...")

banks = ['Bank of America', 'Chase', 'Wells Fargo', 'Citibank', 'US Bank']
transaction_types = ['Deposit', 'Withdrawal', 'Transfer', 'Payment', 'Fee']

financial_data = []
for i in range(1, 201):
    financial_data.append({
        'Transaction_ID': f'FIN{random.randint(1000000, 9999999)}',
        'Account_Number': f'{random.randint(1000000000, 9999999999)}',
        'Account_Holder': random.choice(['John Smith', 'Jane Doe', 'Robert Johnson', 'Mary Williams']),
        'Bank_Name': random.choice(banks),
        'Routing_Number': f'{random.randint(100000000, 999999999)}',
        'Transaction_Type': random.choice(transaction_types),
        'Amount': round(random.uniform(10, 10000), 2),
        'Date': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'Description': random.choice(['Salary Deposit', 'Utility Payment', 'Credit Card Payment', 'Online Purchase', 'ATM Withdrawal']),
        'Balance_After': round(random.uniform(1000, 50000), 2),
        'Merchant': random.choice(['Amazon', 'PayPal', 'Comcast', 'Verizon', 'Netflix', 'Spotify']),
        'Location': f'{random.choice(["New York, NY", "Los Angeles, CA", "Chicago, IL", "Houston, TX"])}',
        'Status': random.choice(['Completed', 'Pending', 'Failed'])
    })

df_financial = pd.DataFrame(financial_data)

# Save to Excel
financial_excel = 'databases/excel/Financial_Transactions.xlsx'
df_financial.to_excel(financial_excel, index=False)
print(f"   ✅ Created: {financial_excel}")

# ============================================================================
# TEXT DATABASES
# ============================================================================
print("\n5. Creating Text Format Databases...")

# Database 5: Configuration Files with Secrets
config_files = [
    {
        'filename': 'databases/configs/production.env',
        'content': '''# PRODUCTION ENVIRONMENT - HIGHLY SENSITIVE
# DO NOT COMMIT TO VERSION CONTROL

# Database Configuration
DB_HOST=prod-db.cluster-123456.us-east-1.rds.amazonaws.com
DB_PORT=5432
DB_NAME=production_database
DB_USER=admin_prod
DB_PASSWORD=SuperSecretProdPassword123!
DB_SSL=true

# API Keys and Secrets
STRIPE_SECRET_KEY=sk_test_FAKESTRIPEKEY1234567890abc
STRIPE_PUBLISHABLE_KEY=pk_live_1234567890abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GOOGLE_API_KEY=AIzaSyD-1234567890abcdefghijklmnopqrstuvwxyz
GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a

# JWT Secrets
JWT_SECRET_KEY=!SuperDuperSecretKeyForJWT1234567890!
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=admin@company.com
SMTP_PASSWORD=EmailPassword123!
SMTP_USE_TLS=true

# Payment Gateway
PAYPAL_CLIENT_ID=AeA6Q8vF_1234567890abcdef
PAYPAL_CLIENT_SECRET=EC1234567890abcdefghijklmnopqrstuvwxyz
PAYPAL_MODE=live

# Encryption Keys
ENCRYPTION_KEY=32CharKeyForAES256Encryption!!
IV_KEY=16CharIVForAES!!

# Admin Credentials
ADMIN_USERNAME=superadmin
ADMIN_PASSWORD=Admin@123#Secure
ROOT_PASSWORD=R00tP@ssw0rd!2024
'''
    },
    {
        'filename': 'databases/configs/database_credentials.txt',
        'content': '''DATABASE CREDENTIALS MASTER LIST
===============================
LAST UPDATED: 2024-01-22
KEEP THIS FILE SECURE!

PRODUCTION DATABASES:
--------------------
1. MySQL Primary
   Host: mysql-prod-01.company.com
   Port: 3306
   Database: app_production
   Username: db_admin_prod
   Password: MySqlProdPass123!
   Connection String: mysql://db_admin_prod:MySqlProdPass123!@mysql-prod-01.company.com:3306/app_production

2. PostgreSQL Backup
   Host: pg-backup-01.company.com
   Port: 5432
   Database: backup_db
   Username: pg_admin
   Password: PgAdmin@Secure456
   Connection String: postgresql://pg_admin:PgAdmin@Secure456@pg-backup-01.company.com:5432/backup_db

3. MongoDB Analytics
   Host: mongodb-cluser.company.com
   Port: 27017
   Database: analytics_db
   Username: mongo_user
   Password: MongoPass789!
   Connection String: mongodb://mongo_user:MongoPass789!@mongodb-cluser.company.com:27017/analytics_db

STAGING DATABASES:
-----------------
1. MySQL Staging
   Username: staging_user
   Password: StagingPass123
   
2. PostgreSQL Staging
   Username: pg_staging
   Password: PgStaging456

DEVELOPMENT DATABASES:
---------------------
1. Local MySQL
   Username: dev_user
   Password: DevPassword789
   
2. Local PostgreSQL  
   Username: local_pg
   Password: LocalPgPass123

BACKUP CREDENTIALS:
------------------
AWS S3 Backup:
  Access Key: AKIAJEXAMPLE123
  Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  Bucket: company-db-backups
  
SFTP Backup Server:
  Host: backup.company.com
  Port: 22
  Username: backup_user
  Password: SftpBackupPass123!
  SSH Key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8w6D... (truncated)
'''
    }
]

for config in config_files:
    with open(config['filename'], 'w') as f:
        f.write(config['content'])
    print(f"   ✅ Created: {config['filename']}")

# Database 6: Log Files with Sensitive Data
log_entries = []
for i in range(100):
    log_time = datetime.now() - timedelta(minutes=random.randint(1, 1000))
    log_type = random.choice(['INFO', 'ERROR', 'WARN', 'DEBUG'])
    
    if log_type == 'ERROR' and random.random() > 0.7:
        entry = f"{log_time.strftime('%Y-%m-%d %H:%M:%S')} ERROR: Payment failed for credit card 4111-1111-1111-1111, customer SSN: 123-45-6789"
    elif log_type == 'DEBUG' and random.random() > 0.8:
        entry = f"{log_time.strftime('%Y-%m-%d %H:%M:%S')} DEBUG: User authentication with password: 'TempPass123!', API Key: sk_test_1234567890abcdef"
    elif log_type == 'INFO' and random.random() > 0.9:
        entry = f"{log_time.strftime('%Y-%m-%d %H:%M:%S')} INFO: Customer data exported - Contains SSNs and credit cards"
    else:
        entry = f"{log_time.strftime('%Y-%m-%d %H:%M:%S')} {log_type}: Regular system operation"
    
    log_entries.append(entry)

with open('databases/logs/application.log', 'w') as f:
    f.write('\n'.join(log_entries))
print(f"   ✅ Created: databases/logs/application.log")

# Database 7: SQL Dump with Sensitive Data
sql_dump = '''-- PRODUCTION DATABASE DUMP
-- WARNING: CONTAINS SENSITIVE INFORMATION
-- GENERATED: 2024-01-22

-- Users Table (Contains PII)
INSERT INTO users (id, username, email, password_hash, ssn, phone, created_at) VALUES
(1, 'jsmith', 'john.smith@company.com', '$2y$10$abc123def456', '123-45-6789', '(555) 123-4567', '2023-01-15 10:30:00'),
(2, 'jdoe', 'jane.doe@company.com', '$2y$10$def456ghi789', '987-65-4321', '(555) 987-6543', '2023-02-20 14:45:00'),
(3, 'bwilson', 'bob.wilson@company.com', '$2y$10$ghi789jkl012', '456-78-9012', '(555) 456-7890', '2023-03-10 09:15:00'),
(4, 'sjohnson', 'sarah.johnson@company.com', '$2y$10$jkl012mno345', '321-54-9876', '(555) 321-0987', '2023-04-05 16:20:00');

-- Payment Methods Table (Contains PCI Data)
INSERT INTO payment_methods (id, user_id, card_type, card_number, expiry_date, cvv, billing_address) VALUES
(1, 1, 'Visa', '4111-1111-1111-1111', '12/25', '123', '123 Main St, New York, NY 10001'),
(2, 2, 'MasterCard', '5500-0000-0000-0004', '06/26', '456', '456 Oak Ave, Los Angeles, CA 90001'),
(3, 3, 'American Express', '3782-822463-10005', '03/24', '789', '789 Pine Rd, Chicago, IL 60007'),
(4, 4, 'Discover', '6011-0000-0000-0004', '09/25', '321', '321 Maple Dr, Houston, TX 77001');

-- Transactions Table
INSERT INTO transactions (id, user_id, amount, card_last4, status, created_at) VALUES
(1001, 1, 149.99, '1111', 'completed', '2024-01-15 10:30:00'),
(1002, 2, 299.50, '0004', 'completed', '2024-01-16 14:45:00'),
(1003, 3, 75.25, '10005', 'failed', '2024-01-17 09:15:00'),
(1004, 4, 450.00, '0004', 'pending', '2024-01-18 16:20:00');

-- API Keys Table (Contains Secrets)
INSERT INTO api_keys (id, service, key_value, created_by) VALUES
(1, 'Stripe', 'sk_test_FAKESTRIPEKEY1234567890abc', 'jsmith'),
(2, 'AWS', 'AKIAIOSFODNN7EXAMPLE', 'jdoe'),
(3, 'SendGrid', 'SG.1234567890abcdef.9876543210', 'bwilson'),
(4, 'Twilio', 'AC1234567890abcdef9876543210', 'sjohnson');

-- Employee Records (HR Data)
INSERT INTO employees (id, full_name, email, ssn, salary, department, hire_date) VALUES
(101, 'Michael Brown', 'michael.brown@company.com', '111-22-3333', 85000, 'Engineering', '2020-03-15'),
(102, 'Emily Davis', 'emily.davis@company.com', '444-55-6666', 92000, 'Sales', '2019-07-22'),
(103, 'David Wilson', 'david.wilson@company.com', '777-88-9999', 78000, 'Marketing', '2021-01-10'),
(104, 'Sarah Miller', 'sarah.miller@company.com', '000-11-2222', 95000, 'Finance', '2018-11-05');
'''

with open('databases/text/production_dump.sql', 'w') as f:
    f.write(sql_dump)
print(f"   ✅ Created: databases/text/production_dump.sql")

# Database 8: CSV Files
csv_files = [
    {
        'filename': 'databases/csv/credit_card_transactions.csv',
        'data': [
            ['Transaction_ID', 'Customer_Name', 'Credit_Card_Number', 'Amount', 'Date', 'Merchant', 'Status'],
            ['TXN1001', 'John Smith', '4532-1488-0343-6467', '149.99', '2024-01-15', 'Amazon', 'Completed'],
            ['TXN1002', 'Jane Doe', '4916-3385-2812-0006', '299.50', '2024-01-16', 'Best Buy', 'Completed'],
            ['TXN1003', 'Robert Johnson', '4485-9753-0912-3456', '75.25', '2024-01-17', 'Starbucks', 'Failed'],
            ['TXN1004', 'Mary Williams', '5111-1111-1111-1118', '450.00', '2024-01-18', 'Apple', 'Pending'],
            ['TXN1005', 'James Brown', '3782-822463-10005', '89.99', '2024-01-19', 'Walmart', 'Completed']
        ]
    },
    {
        'filename': 'databases/csv/employee_ssn_list.csv',
        'data': [
            ['Employee_ID', 'Full_Name', 'SSN', 'Department', 'Salary'],
            ['1001', 'John Smith', '123-45-6789', 'Engineering', '85000'],
            ['1002', 'Jane Doe', '987-65-4321', 'Sales', '92000'],
            ['1003', 'Robert Johnson', '456-78-9012', 'Marketing', '78000'],
            ['1004', 'Mary Williams', '321-54-9876', 'Finance', '95000'],
            ['1005', 'James Brown', '654-32-1098', 'HR', '72000']
        ]
    }
]

for csv_file in csv_files:
    with open(csv_file['filename'], 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(csv_file['data'])
    print(f"   ✅ Created: {csv_file['filename']}")

# ============================================================================
# CREATE SUMMARY REPORT
# ============================================================================
print("\n" + "="*60)
print("📊 DLP TEST DATABASES CREATED SUCCESSFULLY!")
print("="*60)

# Count files
excel_files = [f for f in os.listdir('databases/excel') if f.endswith('.xlsx')]
text_files = []
csv_files_list = []
for root, dirs, files in os.walk('databases'):
    for file in files:
        if file.endswith('.txt') or file.endswith('.env') or file.endswith('.log') or file.endswith('.sql'):
            text_files.append(os.path.join(root, file))
        elif file.endswith('.csv'):
            csv_files_list.append(os.path.join(root, file))

summary = f"""
DATABASE SUMMARY:
----------------

EXCEL DATABASES ({len(excel_files)} files):
  1. Employee_Master_Database.xlsx        - 50 employee records with SSN, salaries
  2. Customer_Database.xlsx              - 100 customers with credit card info
  3. Healthcare_Records.xlsx             - 30 patient records (HIPAA sensitive)
  4. Financial_Transactions.xlsx         - 200 financial transactions

TEXT DATABASES ({len(text_files)} files):
  1. production.env                      - Production configuration with secrets
  2. database_credentials.txt            - Database passwords and connection strings
  3. production_dump.sql                 - SQL dump with sensitive data
  4. application.log                     - Log files with leaked information

CSV DATABASES ({len(csv_files_list)} files):
  1. credit_card_transactions.csv        - Credit card transaction data
  2. employee_ssn_list.csv               - Employee SSN listing

TOTAL FILES: {len(excel_files) + len(text_files) + len(csv_files_list)}
TOTAL SIZE: {sum(os.path.getsize(os.path.join(dirpath, filename)) for dirpath, dirnames, filenames in os.walk('databases') for filename in filenames) / 1024:.1f} KB

SENSITIVE DATA TYPES INCLUDED:
  ✅ Credit Card Numbers
  ✅ Social Security Numbers (SSN)
  ✅ API Keys & Secrets
  ✅ Database Passwords
  ✅ Email Addresses
  ✅ Phone Numbers
  ✅ Bank Account Numbers
  ✅ Medical Information
  ✅ Personal Addresses
  ✅ Salary Information

HOW TO USE WITH DLP SCANNER:
  1. Start your DLP application: python3 app.py
  2. Login as admin
  3. Go to Scanner page
  4. Scan the 'databases' directory
  5. View detected threats in real-time

SCAN COMMAND:
  python3 -c "from scanner_engine import dlp_scanner; result = dlp_scanner.scan_directory('databases'); print(f'Found {{len(result[\"threats\"])}} threats!')"
"""

print(summary)

# Save summary to file
with open('databases/DATABASE_SUMMARY.txt', 'w') as f:
    f.write(summary)

print(f"\n📝 Summary saved to: databases/DATABASE_SUMMARY.txt")
print("\n🚀 Ready for DLP scanning! Your system will detect all these sensitive data leaks.")
