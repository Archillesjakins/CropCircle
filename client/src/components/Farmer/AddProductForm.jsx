import React from 'react';

const AddProductForm = ({ onClose }) => {
    
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
            <div className="bg-white rounded-lg w-full max-w-xs sm:max-w-sm md:max-w-md lg:max-w-lg p-4 sm:p-6 mx-4 sm:mx-0 overflow-y-auto">
                <div className="flex justify-between items-center">
                    <h3 className="text-xl sm:text-2xl px-36 font-bold flex text-gray-800">Add Product</h3>
                    <button onClick={() => onClose()} className="text-gray-500 hover:text-gray-700 text-xl">
                        &times;
                    </button>
                </div>
                
                <p className="text-sm sm:text-lg text-gray-500 text-center mt-2">Kindly fill out this form to add your products.</p>

                <form action="" className="space-y-4 sm:space-y-6 mt-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
                        <div className="flex flex-col">
                            <label htmlFor="name" className="text-gray-700">Product Name</label>
                            <input type="text" id="name" className="border h-10 rounded-lg outline-none px-3 w-full" />
                        </div>
                        <div className="flex flex-col">
                            <label htmlFor="category" className="text-gray-700">Product Category</label>
                            <input type="text" id="category" className="border h-10 rounded-lg outline-none px-3 w-full" />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="description" className="text-gray-700">Product Description</label>
                        <textarea id="description" className="border w-full h-24 outline-none rounded-lg px-3 py-2 resize-none" />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
                        <div className="flex flex-col">
                            <label htmlFor="price" className="text-gray-700">Price per product</label>
                            <input type="text" id="price" className="border h-10 rounded-lg outline-none px-3 w-full" />
                        </div>
                        <div className="flex flex-col">
                            <label htmlFor="image" className="text-gray-700">Product Image</label>
                            <input type="file" id="image" className="border h-10 rounded-lg py-1 px-3 w-full" accept="image/*" />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="quantity" className="text-gray-700">Quantity</label>
                        <input type="text" id="quantity" className="border h-10 rounded-lg outline-none px-3 w-full" />
                    </div>

                    <div className="flex items-center gap-3">
                        <input type="checkbox" id="agreement" className="rounded text-green-600" />
                        <label htmlFor="agreement" className="text-gray-600">
                            You agree to our friendly 
                            <a href="#" className="text-blue-600 underline ml-1">privacy policy</a>
                        </label>
                    </div>

                    <button type="submit" className="w-full h-12 rounded-lg bg-green-600 text-white text-lg font-semibold">
                        Add Product
                    </button>
                </form>
            </div>
        </div>
    );
}

export default AddProductForm;
