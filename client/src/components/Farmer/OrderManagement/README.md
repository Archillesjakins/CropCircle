# Order Management System

## Description

This is an **Order Management System** built using React. It allows the management and tracking of orders within an agricultural marketplace. The system provides functionalities like filtering orders based on various criteria, viewing detailed order information in a modal, and dynamically displaying order cards with different statuses (Completed, Pending, Canceled).

## Features

- **Filter Orders**: Filter orders based on payment method, payment type, order status, and amount range.
- **Order Details**: View detailed information about each order in a modal.
- **Responsive Design**: The application is responsive and adjusts to different screen sizes.
- **Toggle Between Views**: Option to see all orders or limit the display to a specific number of orders.

## Installation

To run the Order Management System locally, follow these steps:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/order-management.git
   cd order-management
2. **Install dependencies**
   ```
   npm install
4. **Start development server**
   ```
      npm start
## Project Structure
```
order-management/
│
├── public/                    # Public assets
│   └── index.html             # Main HTML file
│
├── src/                       # Source files
│   ├── components/            # React components
│   │   ├── OrderManagement.js # Main order management component
│   │   └── OrderData.js       # Sample order data
│   │
│   ├── App.js                 # Main React application file
│   ├── index.js               # React entry point
│   └── index.css              # Global CSS
│
├── package.json               # Project metadata and dependencies
└── README.md                  # Project README
```
## Order Management Page
The main page shows a list of orders with the following features:
- **Filters** 
  - ***Payment Method*** : Filter orders by Visa, Mastercard, Amex, or Mobile Money.
  - ***Payment Type***: Filter orders by Card Payment, Bank Payment, or Mobile Money.
  - ***Order Status***: Filter orders by status: Completed, Pending, Canceled.
  - ***Amount Range***: Set minimum and maximum amounts for filtering orders.
 - **Responsive Design** 
    The application is fully responsive, and it adjusts the layout based on screen size. On smaller screens, the filter section and order cards stack vertically, and the grid layout adjusts accordingly.
   - **Technologies Used**
   - ***React***: JavaScript library for building user interfaces.
   - ***React Icons***: Used for icons like the box icon in the header.
   - ***CSS***: For styling the application.
   - ***React State Management***: Used to handle the order data, filtering, and modal state.
 - **Customizations**
    You can customize the following features:
   - ***Order Data***: Modify the order data inside orderData.js to reflect real data.
   - ***CSS***: Adjust the styles in OrderManagement.css to match the branding and design of your marketplace.
   - ***Filters***: Add or remove filter options depending on your requirements.
- **Preview**
 Here are some previews of how the page looks on different devices:
![Macbook-Air-ORDERMANAGEMENT](https://github.com/user-attachments/assets/c7f85241-11d4-4065-9dce-0d5b3d930bc5)
![iPhone-13-PRO-MAX-ORDERMANAGEMENT](https://github.com/user-attachments/assets/4f3b1af2-fea2-4273-bd23-91d591bd3471)
![iPad-PRO-11-ORDERMANAGEMENT](https://github.com/user-attachments/assets/858a4e57-fe42-4da3-a284-b965778eadd3)
