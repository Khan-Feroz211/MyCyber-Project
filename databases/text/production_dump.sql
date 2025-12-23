-- PRODUCTION DATABASE DUMP
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
(2, 'AWS', 'AKIAFAKEAWSKEY1234567', 'jdoe'),
(3, 'SendGrid', 'SG.1234567890abcdef.9876543210', 'bwilson'),
(4, 'Twilio', 'AC1234567890abcdef9876543210', 'sjohnson');

-- Employee Records (HR Data)
INSERT INTO employees (id, full_name, email, ssn, salary, department, hire_date) VALUES
(101, 'Michael Brown', 'michael.brown@company.com', '111-22-3333', 85000, 'Engineering', '2020-03-15'),
(102, 'Emily Davis', 'emily.davis@company.com', '444-55-6666', 92000, 'Sales', '2019-07-22'),
(103, 'David Wilson', 'david.wilson@company.com', '777-88-9999', 78000, 'Marketing', '2021-01-10'),
(104, 'Sarah Miller', 'sarah.miller@company.com', '000-11-2222', 95000, 'Finance', '2018-11-05');
