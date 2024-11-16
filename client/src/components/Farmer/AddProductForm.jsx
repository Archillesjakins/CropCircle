import { useState } from "react";

const AddProductForm = ({ onClose, products, setProducts }) => {
  const [productName, setProductName] = useState("");
  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");
  const [price, setPrice] = useState("");
  const [image, setImage] = useState(null);
  const [quantity, setQuantity] = useState("");
  const [agreement, setAgreement] = useState(false);
  const [isEdit, setIsEdit] = useState(null);

  const addProduct = (event) => {
    event.preventDefault();

    if (isEdit !== null) {
      // Edit an existing product
      const updatedProducts = products.map((product, index) =>
        index === isEdit
          ? {
              productName,
              category,
              description,
              price,
              image,
              quantity,
              agreement,
            }
          : product
      );
      setProducts(updatedProducts);
      setIsEdit(null);
    } else {
      // Add a new product
      const newProduct = {
        productName,
        category,
        description,
        price,
        image,
        quantity,
        agreement,
        completed: false,
      };
      setProducts([...products, newProduct]);
    }

    // Clear form fields
    setProductName("");
    setCategory("");
    setDescription("");
    setPrice("");
    setImage(null);
    setQuantity("");
    setAgreement(false);
  };

  // Input handlers
  const handleProductNameChange = (event) => setProductName(event.target.value);
  const handleCategoryChange = (event) => setCategory(event.target.value);
  const handleDescriptionChange = (event) => setDescription(event.target.value);
  const handlePriceChange = (event) => setPrice(event.target.value);
  const handleImageChange = (event) => setImage(event.target.files[0]); // Accept File object
  const handleQuantityChange = (event) => setQuantity(event.target.value);
  const handleAgreementChange = (event) => setAgreement(event.target.checked);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 px-4 sm:px-6">
      <div className="bg-white rounded-lg w-full max-w-md sm:max-w-lg md:max-w-xl lg:max-w-2xl p-4 sm:p-6 overflow-y-auto max-h-[90vh]">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg sm:text-2xl font-bold text-gray-800">
            Add Product
          </h3>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 text-2xl"
          >
            &times;
          </button>
        </div>

        <p className="text-sm sm:text-lg text-gray-500 text-center mb-4">
          Kindly fill out this form to add your products.
        </p>
        <form onSubmit={addProduct} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="name" className="text-gray-700">
                Product Name
              </label>
              <input
                type="text"
                id="name"
                value={productName}
                className="border rounded-lg h-10 px-3 w-full outline-none "
                onChange={handleProductNameChange}
              />
            </div>
            <div>
              <label htmlFor="category" className="text-gray-700">
                Product Category
              </label>
              <input
                type="text"
                id="category"
                value={category}
                className="border rounded-lg h-10 px-3 w-full outline-none "
                onChange={handleCategoryChange}
              />
            </div>
          </div>
          <div>
            <label htmlFor="description" className="text-gray-700">
              Product Description
            </label>
            <textarea
              id="description"
              value={description}
              className="border rounded-lg px-3 py-2 w-full h-24 outline-none resize-none "
              onChange={handleDescriptionChange}
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="price" className="text-gray-700">
                Price
              </label>
              <input
                type="text"
                id="price"
                value={price}
                className="border rounded-lg h-10 px-3 w-full outline-none focus:ring-2 focus:ring-green-500"
                onChange={handlePriceChange}
              />
            </div>
            <div>
              <label htmlFor="image" className="text-gray-700">
                Product Image
              </label>
              <input
                type="file"
                id="image"
                className="border rounded-lg h-10 px-3 w-full outline-none focus:ring-2 focus:ring-green-500"
                accept="image/*"
                onChange={handleImageChange}
              />
            </div>
          </div>
          <div>
            <label htmlFor="quantity" className="text-gray-700">
              Quantity
            </label>
            <input
              type="text"
              id="quantity"
              value={quantity}
              className="border rounded-lg h-10 px-3 w-full outline-none focus:ring-2 focus:ring-green-500"
              onChange={handleQuantityChange}
            />
          </div>
          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              id="agreement"
              checked={agreement}
              className="rounded text-green-600"
              onChange={handleAgreementChange}
            />
            <label htmlFor="agreement" className="text-gray-600">
              You agree to our friendly{" "}
              <a href="#" className="text-blue-600 underline">
                privacy policy
              </a>
            </label>
          </div>
          <button
            type="submit"
            className="w-full h-12 bg-green-600 text-white rounded-lg font-semibold "
          >
            Add Product
          </button>
        </form>
      </div>
    </div>
  );
};

export default AddProductForm;
