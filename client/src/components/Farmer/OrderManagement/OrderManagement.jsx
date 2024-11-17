import React, { useState } from "react";
import orderData from "./orderData";
import "./OrderManagement.css";
import { FaBoxOpen } from "react-icons/fa";
const OrderManagement = () => {
  const [showAll, setShowAll] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedOrder, setSelectedOrder] = useState(null);

  // Filter states
  const [selectedPaymentMethod, setSelectedPaymentMethod] = useState("All");
  const [selectedPaymentType, setSelectedPaymentType] = useState("All");
  const [selectedStatus, setSelectedStatus] = useState("All");
  const [minAmount, setMinAmount] = useState("");
  const [maxAmount, setMaxAmount] = useState("");

  const handleToggle = () => {
    setShowAll(!showAll);
  };

  const handleViewDetails = (order) => {
    setSelectedOrder(order);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setSelectedOrder(null);
  };

  const filteredOrders = orderData.filter((order) => {
    const paymentMethod = order.paymentMethod.split(" ")[0];

    const isPaymentMethodMatch =
      selectedPaymentMethod === "All" ||
      paymentMethod === selectedPaymentMethod;
    const isPaymentTypeMatch =
      selectedPaymentType === "All" ||
      order.paymentType === selectedPaymentType;
    const isStatusMatch =
      selectedStatus === "All" || order.status === selectedStatus;
    const isMinAmountMatch =
      minAmount === "" ||
      parseFloat(order.amount.replace("₵", "")) >= parseFloat(minAmount);
    const isMaxAmountMatch =
      maxAmount === "" ||
      parseFloat(order.amount.replace("₵", "")) <= parseFloat(maxAmount);

    return (
      isPaymentMethodMatch &&
      isPaymentTypeMatch &&
      isStatusMatch &&
      isMinAmountMatch &&
      isMaxAmountMatch
    );
  });

  const displayedOrders = showAll ? filteredOrders : filteredOrders.slice(0, 5);

  return (
    <div className="order-management">
      <div className="order-header">
        <div className="header-content">
          <FaBoxOpen className="header-icon" />
          <div>
            <h2>Order Management</h2>
            <p className="header-subtitle">
              Track and manage your orders seamlessly
            </p>
          </div>
        </div>

        <button onClick={handleToggle} className="see-all-orders">
          {showAll ? "Show Less" : "See All Orders"}
        </button>
      </div>

      <div className="filter-section">
        <select
          value={selectedPaymentMethod}
          onChange={(e) => setSelectedPaymentMethod(e.target.value)}
          className="filter-select"
        >
          <option value="All">All Payment Methods</option>
          <option value="Visa">Visa</option>
          <option value="Mastercard">Mastercard</option>
          <option value="Amex">Amex</option>
          <option value="MobileMoney">Mobile money</option>
        </select>

        <select
          value={selectedPaymentType}
          onChange={(e) => setSelectedPaymentType(e.target.value)}
          className="filter-select"
        >
          <option value="All">All Payment Types</option>
          <option value="Card payment">Card Payment</option>
          <option value="Bank payment">Bank Payment</option>
          <option value="Mobile money">Mobile Money</option>
        </select>

        <select
          value={selectedStatus}
          onChange={(e) => setSelectedStatus(e.target.value)}
          className="filter-select"
        >
          <option value="All">All Status</option>
          <option value="Completed">Completed</option>
          <option value="Pending">Pending</option>
          <option value="Canceled">Canceled</option>
        </select>

        <input
          type="text"
          value={minAmount}
          onChange={(e) => setMinAmount(e.target.value)}
          placeholder="Min Amount"
          className="filter-input"
        />

        <input
          type="text"
          value={maxAmount}
          onChange={(e) => setMaxAmount(e.target.value)}
          placeholder="Max Amount"
          className="filter-input"
        />
      </div>

      <div className="order-list">
        {displayedOrders.map((order) => (
          <div
            key={order.id}
            className={`order-card ${order.status.toLowerCase()}`}
          >
            <div className="order-info">
              <p>{order.paymentMethod}</p>
              <span>{order.paymentType}</span>
            </div>
            <div className="order-details">
              <p className="order-amount">{order.amount}</p>
              <span className="order-date">{order.date}</span>
            </div>
            <div className={`order-status ${order.status.toLowerCase()}`}>
              {order.status}
            </div>
            <button
              onClick={() => handleViewDetails(order)}
              className="view-details"
            >
              View Details
            </button>
          </div>
        ))}
      </div>

      {isModalOpen && selectedOrder && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <button onClick={closeModal} className="close-modal">
              &times;
            </button>
            <h3>Order Details</h3>
            <p>
              <strong>Customer Name:</strong> {selectedOrder.customerName}
            </p>
            <p>
              <strong>Payment Method:</strong> {selectedOrder.paymentMethod}
            </p>
            <p>
              <strong>Payment Type:</strong> {selectedOrder.paymentType}
            </p>
            <p>
              <strong>Amount:</strong> {selectedOrder.amount}
            </p>
            <p>
              <strong>Date:</strong> {selectedOrder.date}
            </p>
            <p>
              <strong>Status:</strong> {selectedOrder.status}
            </p>
            <p>
              <strong>Address:</strong> {selectedOrder.address}
            </p>
            <p>
              <strong>Phone Number:</strong> {selectedOrder.phoneNumber}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrderManagement;
