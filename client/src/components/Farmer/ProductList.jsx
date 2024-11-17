import { Edit, Ellipsis, MoveLeft, MoveRight, Trash2 } from "lucide-react";
import productData from "../../utils/constants"; //renamed the import to avoid conflict since am having additional product state created with usestate
import { useState } from "react";

const ProductList = () => {
    const [showDetails, setShowDetails] = useState({});
    const [currentPage, setCurrentPage] = useState(1);
    const [products, setProducts] = useState(productData);
    const [isEditing, setIsEditing] = useState(false);
    const [currentEdit, setCurrentEdit] = useState(null);
    

    const itemsPerPage = 10;// Seting  the number of products per page
    const totalPages = Math.ceil(products.length / itemsPerPage);

    const toggleDetails = (index) => {
        setShowDetails((prevState) => ({
            ...prevState,
            [index]: !prevState[index],
        }));
    };

    const handleNextPage = () => {
        setCurrentPage((prevPage) => Math.min(prevPage + 1, totalPages));
    };

    const handlePreviousPage = () => {
        setCurrentPage((prevPage) => Math.max(prevPage - 1, 1));
    };

    const handlePageJump = (pageNumber) => {
        setCurrentPage(pageNumber);
    };
  
    const startIndex = (currentPage - 1) * itemsPerPage;
    const currentProducts = products.slice(startIndex, startIndex + itemsPerPage);

    const handleDelete = (index) => {
        // using window.confirm to creates a dialog with the message
        const confirmDelete = window.confirm("Are you sure you want to delete this product?");
    if (confirmDelete) {
        const updatedProducts = products.filter((_, i) => i !== startIndex + index);
        setProducts(updatedProducts);
    }
    };

    const handleEditClick = (product, index) => {
        setIsEditing(true);
        setCurrentEdit({ ...product, index: startIndex + index });
    };

    const handleEditChange = (event) => {
        const { name, value } = event.target;
        setCurrentEdit((prevEdit) => ({
            ...prevEdit,
            [name]: value,
        }));
    };

    const handleEditSave = () => {
        const updatedProducts = products.map((product, i) =>
            i === currentEdit.index ? currentEdit : product
        );
        setProducts(updatedProducts);
        setIsEditing(false);
        setCurrentEdit(null);
    };
    
      
    return (
        <div className="flex flex-col items-center py-16 px-4 sm:px-8">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-5">
                {currentProducts.map((product, index) => (
                    <div key={index} className="border w-full sm:w-auto  p-4 mb-4 rounded-lg shadow-lg transition-all border-green-400 transform hover:scale-105 hover:shadow-2xl duration-500">
                        <div className="flex justify-center mb-4">
                            <img src={product.image} alt="" className="w-32 h-24 object-cover" />
                        </div>
                        <div className="flex justify-between items-center">
                            <h3 className="font-bold py-2 text-green-500 text-sm sm:text-base ">{product.name}</h3>
                            <Ellipsis onClick={() => toggleDetails(index)} className="cursor-pointer" />
                        </div>
                        <p className="text-sm sm:text-base">GHS{product.price}</p>
                        <p className="text-sm sm:text-base">{product.quantity}</p>

                        {showDetails[index] && (
                            <div className="text-sm">
                                <p className="py-1 text-gray-600 font-medium">{product.description}</p>
                                <p className="text-green-500">{product.category}</p>
                            </div>
                        )}

                        <div className="flex justify-end gap-4 mt-2">
                            <Edit onClick={() => handleEditClick(product, index)} className="text-blue-500 w-4 cursor-pointer" />
                            <Trash2 className="text-red-400 w-4 cursor-pointer" onClick={() => handleDelete(index)} />
                        </div>
                    </div>
                ))}
            </div>

            {/*Using button to control the  Pagination  */}
            <div className="flex justify-center gap-4 mt-8">
                <button
                    onClick={handlePreviousPage}
                    disabled={currentPage === 1}
                    className="px-4 py-2 text-gray-500"
                >
                    <MoveLeft />
                </button>
                {[...Array(totalPages)].map((_, pageIndex) => (
                    <button
                        key={pageIndex}
                        onClick={() => handlePageJump(pageIndex + 1)}
                        className={`px-4 py-2 ${
                            currentPage === pageIndex + 1 ? "text-green-500 font-bold" : "text-gray-500"
                        }`}
                    >
                        {pageIndex + 1}
                    </button>
                ))}
                <button
                    onClick={handleNextPage}
                    disabled={currentPage === totalPages}
                    className="px-4 py-2 text-gray-500"
                >
                    <MoveRight />
                </button>
            </div>

           
            
            {/* Creating the Editing Modal form */}
            {isEditing && (
                <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center">
                    <div className="bg-white p-6 rounded shadow-lg w-full max-w-md">
                        <h2 className="text-xl font-semibold mb-4">Edit Product</h2>
                        <input
                            type="text"
                            name="name"
                            value={currentEdit.name}
                            onChange={handleEditChange}
                            className="w-full mb-2 p-2 border"
                            placeholder="Name"
                        />
                        <input
                            type="number"
                            name="price"
                            value={currentEdit.price}
                            onChange={handleEditChange}
                            className="w-full mb-2 p-2 border"
                            placeholder="Price"
                        />
                        <input type="text" 
                        
                        name = "quantity"
                        value={currentEdit.quantity}
                        onChange={handleEditChange}
                        className="w-full mb-2 p-2 border"
                        placeholder="Quantity"
                         />
                        <textarea
                            name="description"
                            value={currentEdit.description}
                            onChange={handleEditChange}
                            className="w-full mb-2 p-2 border"
                            placeholder="Description"
                        />
                        <button onClick={handleEditSave} className="bg-green-500 text-white px-4 py-2 rounded mr-2">
                            Save
                        </button>
                        <button onClick={() => setIsEditing(false)} className="bg-red-400 text-white px-4 py-2 rounded">
                            Cancel
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ProductList;
