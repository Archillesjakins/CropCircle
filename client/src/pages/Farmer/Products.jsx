import { useState } from 'react';
import ProductList from '../../components/Farmer/ProductList';
import AddProductForm from '../../components/Farmer/AddProductForm';

const Products = () => {
  const [modalOpen, setModalOpen] = useState(false);
// set the modal open when it's true
  const handleAddProduct = () => {
    setModalOpen(true);
  };
// set the modal to close when it's false(submitting)
  const handleCloseModal = () => {
    setModalOpen(false);
  };
  
  
  return (
    <div>
      <div className="flex sm:flex-row justify-between items-center mt-8 px-4 sm:px-8">
        <h2 className="m-4 sm:m-8 text-2xl sm:text-3xl md:text-4xl underline">PRODUCTS</h2>
        <div className="border rounded-lg h-10 px-4 sm:px-7 m-4 sm:m-8 bg-green-600">
          <button className="py-2 text-white" onClick={handleAddProduct}>
            Add Products
          </button>
        </div>
      </div>

      <ProductList />

      {modalOpen && (
        <div className="fixed inset-0  flex items-center justify-center bg-black bg-opacity-50 z-50">
          <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-lg relative">
            <button
              className="absolute top-4 right-4 text-gray-500"
              onClick={handleCloseModal}
            > 
              &times; {/* Closeing the button */}
            </button>
            <AddProductForm onClose={handleCloseModal} />
          </div>
        </div>
      )}
    </div>
  );
};

export default Products;
