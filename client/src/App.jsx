import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import NotFound from './pages/NotFound';
import Overview from './pages/Farmer/Overview';
import Orders from './pages/Farmer/Orders';
import Products from './pages/Farmer/Products';
import FarmerLayout from './pages/Farmer/FarmerLayout';
import AddProductForm from './components/Farmer/AddProductForm';
import Feedback from './pages/Admin/Feedback';
import FlaggedItems from './pages/Admin/FlaggedItems';
import VerificationQueue from './pages/Admin/VerificationQueue';
import AdminLayout from './pages/Admin/AdminLayout';
import CustomerLayout from './pages/Customer/CustomerLayout';
import CartPage from './pages/Customer/CartPage';
import OrderTracking from './pages/Customer/OrderTracking';
import Homepage from './pages/Customer/Homepage';
import CustomerLogin from './auth/Customer/CustomerLogin';
import AdminLogin from './auth/Admin/AdminLogin';
import FarmerLogin from './auth/Farmer/FarmerLogin';
import FarmerSignUp from './auth/Farmer/FarmerSignUp';
import Home from './pages';
import CustomerSignUp from './auth/Customer/CustomerSignUp';
import ProductList from './components/Farmer/ProductList';


function App() {
  return (
    <Router>
      <Routes>

        <Route path='/' element={<Home />} />

        <Route path="/customer/login" element={<CustomerLogin />} />
        <Route path="/customer/signup" element={<CustomerSignUp />} />

        <Route path="/admin/login" element={<AdminLogin />} />

        <Route path="/farmer/login" element={<FarmerLogin />} />
        <Route path="/farmer/signup" element={<FarmerSignUp />} />

        <Route

          path="/farmer/*"
          element={
            <FarmerLayout>
              <Routes>
                <Route path="product" element={<Products />} />
                <Route path="orders" element={<Orders />} />
                <Route path="overview" element={<Overview />} />
              </Routes>
            </FarmerLayout>
          }

        />

        <Route
          path="/admin/*"
          element={
            <AdminLayout>
              <Routes>
                <Route path="feedback" element={<Feedback />} />
                <Route path="flagged-items" element={<FlaggedItems />} />
                <Route path="verification-queue" element={<VerificationQueue />} />
              </Routes>
            </AdminLayout>
          }
        />

        <Route
          path="/customer/*"
          element={
            <CustomerLayout>
              <Routes>
                <Route path="homepage" element={<Homepage />} />
                <Route path="cartitems" element={<CartPage />} />
                <Route path="orders" element={<OrderTracking />} />

              </Routes>
            </CustomerLayout>
          }
        />


        {/* 404 Page */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Router>
  );
}

export default App;
