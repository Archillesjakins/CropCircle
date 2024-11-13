import React from "react";
import AdminBg from "../../assets/Background-images/side-view-women-shaking-hands.jpeg";

const AdminLogin = () => {
  const formData = {
    email: "",
    password: "",
  }
  const dummyData = {
    email: "admin@admin.com",
    password: "123",
  }

  const [error, setError] = React.useState("");

  const [form, setForm] = React.useState(formData);
  function HandleChange(e){
    setForm({...form,[e.target.name]:e.target.value})
    console.log(form);
  }

  function HandleSubmit(e){
    e.preventDefault();
    if(form.email === "" || form.password === ""){
      alert("Please fill the form")
      return;
    }
    try{
       const response = fetch("http://localhost:8000/api/admin/login", form)
       if(response.status === 200){
         alert("Login Successful")
         window.location.href = "/admin/dashboard"
         return;
       }
       else{
         alert("Invalid Credentials")
         return;
       }
    }
    catch(error){
      setError(error);
    }
  
    console.log("Results",form);
  }
  return (
    <div
      className="flex items-center justify-center  bg-cover min-h-screen"
      style={{ backgroundImage: `url(${AdminBg})` }}
    >
      <div className="p-20 w-full max-w-lg bg-gray-300 rounded-lg shadow-lg">
      <h1 className="font-bold text-3xl text-center text-green-600 mb-4">CROPCIRCLE</h1>
      <h2 className="text-xl font-semibold text-center">Welcome Back, Admin</h2>
      <p className="text-center mb-6">Sign In to continue</p>

        <form onSubmit={HandleSubmit} action="" className="space-y-4">
          <input
            type="email"
            placeholder="Email"
            name="email"
            onChange={HandleChange}
            className="w-full p-3 rounded-md border border-gray-400 focus:outline-none focus:border-green-500"
          />
          <input
            type="password"
            placeholder="Password"
            className="w-full p-3 rounded-md border border-gray-400 focus:outline-none focus:border-green-500"
          />
          <button
            type="submit"
            className="w-full py-3 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 transition"
          >
            Sign In
          </button>
          <p className="text-center mt-4 text-sm">
            <a href="" className="text-gray-600 hover:underline">
              Forgot Password?
            </a>
          </p>
        </form>
      </div>
    </div>
  );
};

export default AdminLogin;
