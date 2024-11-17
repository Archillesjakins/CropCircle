import React from 'react';
import '../../styles/Farmer/Overview.css';
import testSvg from '../../assets/SVGs/chart-line.svg';
import truck from '../../assets/SVGs/truck-fast.svg';
import cart from '../../assets/SVGs/cart-shopping.svg';
import list from '../../assets/SVGs/list-check.svg';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowRight } from '@fortawesome/free-solid-svg-icons';
import orderData from '../../components/Farmer/OrderManagement/orderData';

const SalesAnalytics = () => {
  // Calculate total sales
  const totalSales = orderData.reduce((sum, order) => sum + parseFloat(order.amount.replace('₵', '')), 0);

  // Identify the top-selling product (replace this logic with an actual top-selling product calculation)
  const topSellingProduct = orderData.length
    ? orderData.reduce((topProduct, order) =>
        parseFloat(order.amount.replace('₵', '')) > parseFloat(topProduct.amount.replace('₵', '')) ? order : topProduct
      )
    : null;

  // Filter products to count only completed deliveries
  const completedDeliveries = orderData.filter(order => order.status === 'Completed').length;

  return (
    <div className="overview">
      <div className="saleAnalysis">
        <div className="totalSale">
          <p><strong>¢{totalSales.toFixed(2)}</strong></p>
          <h3>Sales <img className='images' src={testSvg} alt="Sales Chart Icon" /></h3>
        </div>
        <div className="totalSale">
          <p><strong>{orderData.length}</strong></p>
          <h3>Orders <img className='images' src={truck} alt="Truck Icon" /></h3>
        </div>
        <div className="topSellingProduct">
          <p><strong>{topSellingProduct?.product || "No Sales Yet"}</strong></p>
          <h3>Top Selling Product <img className='images' src={cart} alt="Shopping Cart Icon" /></h3>
        </div>
        <div className="totalSale">
          <p><strong>{completedDeliveries}</strong></p>
          <h3>Deliveries Made <img className='images' src={list} alt="Checklist Icon" /></h3>
        </div>
      </div>

      <h1>Recent Orders</h1>
      <table>
        <thead>
          <tr>
            <th>Customer</th>
            <th>Amount</th>
            <th>Date</th>
            <th>Status</th>
            <th>Payment Method</th>
          </tr>
        </thead>
        <tbody>
          {orderData.map((order) => (
            <tr key={order.id}>
              <td>{order.customerName}</td>
              <td>{order.amount}</td>
              <td>{order.date}</td>
              <td>{order.status}</td>
              <td>{order.paymentMethod}</td>
            </tr>
          ))}
        </tbody>
      </table>
      
      <a href="#" className="link">More detail <FontAwesomeIcon icon={faArrowRight} /></a>
    </div>
  );
};

export default SalesAnalytics;
