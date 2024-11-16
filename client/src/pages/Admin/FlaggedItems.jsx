import "../../styles/Admin/FlaggedItems.css";
import React, { useState } from 'react';
import redTomatoImage from '../../assets/images/red_tomatoes1.png';
import redTomatoesImage from '../../assets/images/red_tomatoes2.png';
import greenPepperImage from '../../assets/images/green_pepper1.png';
import GreenPepperImage from '../../assets/images/green_pepper2.png';
import cabbageImage from '../../assets/images/cabbage1.png';
import cabbageImageReceived from '../../assets/images/cabbage2.png';
import carrotImage from '../../assets/images/carrot1.png';
import carrotImageReceived from '../../assets/images/carrot2.png';
import sweetPotatoImage from '../../assets/images/sweet-potatoes1.png';
import sweetPotatoImageReceived from '../../assets/images/sweet-potatoes2.png';
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBoxArchive, faTrashCan } from "@fortawesome/free-solid-svg-icons";

// Sample data for flagged items
const flaggedItemsData = [
  {
    id: 1,
    customerName: 'James Duntu',
    email: 'jamesduntu@gmail.com',
    productName: 'Red Tomato',
    productImage: redTomatoImage,
    flaggedReason: 'The tomato was...',
    description: 'The tomato was found to be rotten upon delivery.',
    price: 'GHC99.00',
    date: 'Jan 17, 2022',
    paymentMethod: 'Mobile Money',
    status: 'Resolved',
    productReceivedImage: redTomatoesImage,
  },
  {
    id: 2,
    customerName: 'Jake Williams',
    email: 'jakewil@gmail.com',
    productName: 'Green Pepper',
    productImage: greenPepperImage,
    flaggedReason: 'The products were...',
    description: 'Product expired a week before delivery.',
    price: 'GHC45.00',
    date: 'Feb 2, 2024',
    paymentMethod: 'Credit Card',
    status: 'Pending',
    productReceivedImage: GreenPepperImage,
  },
  {
    id: 3,
    customerName: 'Samuel Owusu',
    email: 'samuelowusu@gmail.com',
    productName: 'Cabbage',
    productImage: cabbageImage,
    flaggedReason: 'The cabbage was...',
    description: 'The cabbage was wilted and overripe upon delivery.',
    price: 'GHC35.00',
    date: 'Feb 15, 2024',
    paymentMethod: 'Cash on Delivery',
    status: 'Resolved',
    productReceivedImage: cabbageImageReceived,
  },
  {
    id: 4,
    customerName: 'Martha Mensah',
    email: 'marthamensah@gmail.com',
    productName: 'Carrot',
    productImage: carrotImage,
    flaggedReason: 'The carrots were...',
    description: 'The carrots had signs of mold and were soft.',
    price: 'GHC25.00',
    date: 'Feb 18, 2024',
    paymentMethod: 'Mobile Money',
    status: 'Pending',
    productReceivedImage: carrotImageReceived,
  },
  {
    id: 5,
    customerName: 'Kwame Agyemang',
    email: 'kwameagyemang@gmail.com',
    productName: 'Sweet Potato',
    productImage: sweetPotatoImage,
    flaggedReason: 'The sweet potatoes were...',
    description: 'The sweet potatoes had bruises and were not fresh.',
    price: 'GHC50.00',
    date: 'Feb 20, 2024',
    paymentMethod: 'Debit Card',
    status: 'Resolved',
    productReceivedImage: sweetPotatoImageReceived,
  }
];

const FlaggedItems = () => {
  const [items, setItems] = useState(flaggedItemsData);
  const [selectedItem, setSelectedItem] = useState(null);
  const [showModal, setShowModal] = useState(false);

  const handleArchive = (id) => {
    setItems(items.filter(item => item.id !== id));
  };

  const handleDelete = (id) => {
    if (window.confirm('Are you sure you want to delete this item?')) {
      setItems(items.filter(item => item.id !== id));
    }
  };

  const handleRowClick = (item) => {
    setSelectedItem(item);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedItem(null);
  };

  return (
    <div className="admin-page-flagged-items">
    <div className="flagged-items-container">
      <div className="flagged-heading">
        <h2>Flagged Items</h2>
        <p>Here are the items flagged by customers for review.</p>
      </div>

      <div className="flagged-items-list">
        {items.map(item => (
          <div key={item.id} className="flagged-item-row" onClick={() => handleRowClick(item)}>
            <div className="flagged-item">
            <div className="item-product">
                <h4>{item.customerName}</h4>
                <p>{item.email}</p>
              </div>
              <div className="product-details">
                <img src={item.productImage} alt={item.productName} className="product-image" />
                <h4>{item.productName}</h4>
              </div>
              <div className="item-product">
                <h4>{item.productName}</h4>
                <p>{item.flaggedReason}</p>
              </div>
              <div className="item-price">
                <p>{item.price}</p>
                <p>{item.date}</p>
              </div>
              <div className="item-actions">
                {/* Archive and Delete buttons */}
                <button className="action-button archive" onClick={(e) => { e.stopPropagation(); handleArchive(item.id); }}>
                  <FontAwesomeIcon icon={faBoxArchive} />
                </button>
                <button className="action-button delete" onClick={(e) => { e.stopPropagation(); handleDelete(item.id); }}>
                  <FontAwesomeIcon icon={faTrashCan} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Modal */}
      {showModal && selectedItem && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Product Detail</h2>
            <div className="modal-header">
              <img
                src={selectedItem.productImage}
                alt={selectedItem.productName}
                className="modal-product-image"
              />
              <div className="modal-header-content">
                <h3>{selectedItem.productName}</h3>
                <p>{selectedItem.description}</p>
              </div>
            </div>
            <div className="modal-details">
              <div className="detail-row">
                <span className="label">Customer</span>
                <span className="value">{selectedItem.customerName}</span>
              </div>
              <div className="detail-row">
                <span className="label">Email</span>
                <span className="value">{selectedItem.email}</span>
              </div>
              <div className="detail-row">
                <span className="label">Payment Method</span>
                <span className="value">{selectedItem.paymentMethod}</span>
              </div>
              <div className="detail-row">
                <span className="label">Date</span>
                <span className="value">{selectedItem.date}</span>
              </div>
              <div className="detail-row">
                <span className="label">Status</span>
                <span className={`status ${selectedItem.status.toLowerCase()}`}>{selectedItem.status}</span>
              </div>
              <div className="detail-row">
                <span>Total Price</span> {selectedItem.price}
              </div>
              <div className="detail-row">
                <span>Product Received Image</span>
                <img src={selectedItem.productReceivedImage} alt="Received" className="received-image" />
              </div>
            </div>
            <button className="close-button" onClick={closeModal}>Close</button>
          </div>
        </div>
      )}
    </div>
    </div>
  );
};

export default FlaggedItems
