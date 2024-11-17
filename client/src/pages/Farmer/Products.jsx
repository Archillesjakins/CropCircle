import { useState } from "react";
import ProductList from "../../components/Farmer/ProductList";
import AddProductForm from "../../components/Farmer/AddProductForm";

const Products = () => {
  const [modalOpen, setModalOpen] = useState(false);
  const [products, setProducts] = useState([]);
 
  const handleAddProduct = () => {
    setModalOpen(true);
  };

  const handleCloseModal = () => {
    setModalOpen(false);
  };
  
  const handleSaveProduct = (newProduct) => {
    setProducts((prevProducts) => [...prevProducts, newProduct]);
    setModalOpen(false);
  };

  return (
    <div>
      <div className="flex flex-wrap sm:flex-row justify-between items-center mt-8 px-4 sm:px-8">
        <h2 className="m-4 sm:m-8 text-2xl sm:text-3xl md:text-4xl underline">
          PRODUCTS
        </h2>
        <div className="border rounded-lg h-10 px-4 sm:px-7 m-4 sm:m-8 bg-green-600">
          <button className="py-2 text-white" onClick={handleAddProduct}>
            Add Products
          </button>
        </div>
      </div>


      <ProductList />

      {modalOpen && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50 px-4 sm:px-6">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-md sm:max-w-lg md:max-w-xl lg:max-w-2xl p-4 sm:p-6 relative max-h-[90vh] overflow-y-auto">
            <button
              className="absolute top-4 right-4 text-gray-500 hover:text-gray-700 text-2xl"
              onClick={handleCloseModal}
            >
              &times;
            </button>
            <AddProductForm onClose={handleCloseModal} onSave={handleSaveProduct} products={products}
          setProducts={setProducts}/>
          </div>
        </div>
      )}
    </div>
  );
};

export default Products;
