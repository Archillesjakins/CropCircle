import React, { useState } from 'react';
import '@fortawesome/fontawesome-free/css/all.min.css';
import { Link } from 'react-router-dom';
import leafImage from '../../assets/images/leaf.png';

const FarmerLayout = ({ children }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);

  const toggleSidebar = () => {
    setIsCollapsed(!isCollapsed);
  };

  const sidebarLinks = [
    { to: '/farmer/overview', icon: 'fas fa-chart-pie', label: 'Overview' },
    { to: '/farmer/product', icon: 'fas fa-box', label: 'Products' },
    { to: '/farmer/orders', icon: 'fas fa-shopping-cart', label: 'Orders' },
  ];

  return (
    <div className="relative flex h-screen">
      {/* Sidebar */}
      <aside
        className={`grid grid-rows-12 z-50 h-full bg-green-700 text-white shadow-lg transition-all duration-300 ${isCollapsed ? 'lg:w-16 w-0' : 'w-64 absolute lg:relative'
          }`}
      >
        {/* Sidebar Header */}
        <div className="flex items-center justify-between row-span-2 p-4">
          {!isCollapsed && (
            <div className="flex items-center space-x-2">
              <img src={leafImage} alt="logo" className="w-8 h-8" />
              <span className="text-2xl font-semibold">CropCircle</span>
            </div>
          )}
          <button
            className="p-2 text-white "
            onClick={toggleSidebar}
          >
            <i className={`fas ${isCollapsed ? 'fa-bars' : 'fa-times'}`}></i>
          </button>
        </div>

        {/* Sidebar Links */}
        <div className='flex flex-col justify-between row-span-10'>
          
        
    
        
        <div className="p-4 space-y-4">
        {sidebarLinks.map((link, index) => (
  <div key={index}>
    <Link to={link.to} className="flex items-center p-3 text-lg text-white transition-colors rounded-lg hover:bg-green-800">
      <i className={`mr-3 ${link.icon}`}></i>
      {!isCollapsed && <span className="ml-3">{link.label}</span>}
    </Link>
  </div>
))}
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 mt-auto space-y-4">
          <div className="flex items-center p-3 transition-colors rounded-lg hover:bg-green-800">
            <i className="fas fa-cog"></i>
            {!isCollapsed && <span className="ml-3">Settings</span>}
          </div>
          <div className="flex items-center p-3 transition-colors rounded-lg hover:bg-green-800">
            <i className="fas fa-sign-out-alt"></i>
            {!isCollapsed && <span className="ml-3">Log Out</span>}
          </div>
        </div>
        </div>
      </aside>

      {!isCollapsed && (
        <div
          className="fixed inset-0 z-40 bg-black bg-opacity-50 sm:block lg:hidden"
          onClick={toggleSidebar}
        ></div>
      )}
      
      {/* Main Content */}
      <div className="flex-1 p-4 overflow-auto bg-gray-100 ">
        {/* Header */}
        <header className="flex items-center justify-between gap-2 p-4 mb-6 bg-white rounded-lg shadow-md">
          <button
            className="p-2 text-green-700 lg:hidden"
            onClick={toggleSidebar}
          >
            <i className="fas fa-bars"></i>
          </button>
          <div className="flex items-center w-full gap-4">
            <input
              type="text"
              placeholder="Search for product, customer, etc..."
              className="w-full p-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500"
            />
            <i className="text-green-600 fas fa-search"></i>
          </div>
          <div className="flex items-center gap-4">
            <div className="relative">
              <i className="text-xl text-gray-600 fa-regular fa-bell"></i>
              <span className="absolute top-0 right-0 flex items-center justify-center w-4 h-4 text-xs text-white bg-red-600 rounded-full">
                3
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <img
                src="https://placehold.co/40x40"
                alt="User profile"
                className="w-20 rounded-full"
              />
              <div className="flex-col hidden text-sm md:flex">
                <p className="font-semibold">Evelyn</p>
                <p className="text-gray-600">Farmer</p>
              </div>
            </div>
          </div>
        </header>

        {/* Main Section */}
        <section className="p-6 bg-white rounded-lg shadow-md">{children}</section>
      </div>
    </div>
  );
};

export default FarmerLayout;
