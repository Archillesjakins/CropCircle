import React, { useEffect, useRef } from 'react';
import { useState } from 'react';
import { Search, Bell,ChevronDown, ChevronUp,Home, User,ShoppingCart, HelpCircle, LogOut, UserCheck,Store, Icon} from 'lucide-react';


const CustomerLayout = ({children}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [Notification, setNotification] = useState(1);
  const [cartcount, setCartCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) =>{
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)){
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);
  useEffect(() =>{
    const updateCartCount = () => {
      setCartCount(3);
    };
    updateCartCount();
  ``}, []);

  const handleSearch = (e) => {e.preventDefault(); console.log('Searching...', searchQuery);};       
  const handleNotification = () => {setNotification(prev => prev + 1)};

  const menuItems = [
    {Icon: Home, label: 'Home', href: 'homepage'},
    {Icon:ShoppingCart, label: 'Cart', href: 'Cartitems'},
    {Icon: Store, label: 'Orders', href: 'Orders'},
    {Icon: User, label: 'Profile', href: 'profile'},
    {Icon: HelpCircle, label: 'Help Center', href: 'help'},
    {Icon: LogOut, label: 'Logout', href: 'logout', className: 'text-red-600 hover:bg-red-50'},
  ];
  
  return (
    <div className='flex flex-col min-h-screen bg-gray-50'> 
      <header className='sticky top-0 z-50 bg-white border-b border-gray-200'>
        <div className='w-full bg-green-200 border-b'>
          <div className='px-0 py-2 mx-auto max-w-7xl'>
            <div className='flex items-center justify-between'>

              {/*logo */}
              <div className='flex items-center pr-10 '>
              < a href='homepage'><button className='flex items-center gap-2 p-2 transition-colors rounded-lg hover:bg-green-300' href='Homepage'>
                <div className='flex items-center justify-center w-10 h-10 bg-green-100 rounded-full'>
                  <span className='text-2xl text-green-700'>CC</span>
                </div>
                  <span className='hidden text-xl font-semibold text-gray-700 sm:block'>CropCircle</span>
                </button></a>
              </div>
              {/*Search Bar */}
              {isSearchOpen &&(
                <form onSubmit={handleSearch} className='flex-1 max-w-3xl mx-4 sm:w-auto'>
                  <div className='flex items-center border border-gray-300 bg-gray-50 rounded-xl sm:w-auto'>
                    <input 
                      type="text"
                      value={searchQuery} 
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder='Search for products, customers, etc..' 
                      className='w-full ml-2 text-sm bg-transparent border-none text-gray-950 focus:outline-none'
                    />
                  <button type='submit' className='px-8 py-2 bg-green-300 rounded-r-md hover:bg-green-400 sm:px-auto'>
                    Search 
                  </button>
                  </div>
                </form>
              )}

              {/*Right Section of the navigation Bar*/}
              <div className='flex gap-4 items-right'>
                <button 
                  onClick={() => setIsSearchOpen(!isSearchOpen)} 
                  className='p-2 transition-colors rounded-lg hover:bg-green-300 '>
                  <Search className='w-6 h-6 text-gray-700'/>
                </button> 

                <button className='relative p-2 text-gray-600 transition-colors hover:bg-green-300 rounded-s-md'>
                  <Bell className='w-5 h-5 text-gray-700' />
                  {Notification > 0 && (
                    <span className='absolute top-0 right-0 flex items-center justify-center w-5 h-5 text-xs font-bold text-white transform bg-red-500 rounded-full translate-x-1/3 -translate-y-1/3'>
                       {Notification} 
                    </span>
                  )}
                </button>
                
                <button className='relative p-2 text-gray-600 transition-colors hover:bg-green-300 rounded-s-md'>
                   <a href='Cartitems'><ShoppingCart className='w-5 h-5 text-gray-700' /></a>
                   {cartcount > 0 && (
                      <span className='absolute top-0 right-0 flex items-center justify-center w-5 h-5 text-xs font-bold text-white transform bg-red-500 rounded-full translate-x-1/3 -translate-y-1/3'>
                         {cartcount} 
                      </span>
                   )}
                
                </button> 
                 
                {/* User Menu*/}  
                <div className='relative' ref={dropdownRef}>
                  <button onClick={() => setIsOpen(!isOpen)}
                    className='flex items-center gap-2 p-2 transition-colors rounded-lg hover:bg-green-300'
                    >
                      <div className='flex items-center justify-center w-8 h-8 bg-green-100 rounded-full'>
                        <span className='text-green-700'></span>
                        <UserCheck/>
                      </div>
                      <span className='hidden font-medium text-gray-700 sm:block' >Hi, Ideation Axis</span>
                      {isOpen ? (
                        <ChevronUp className='hidden w-6 h-6 text-gray-700 sm:block' />)
                      : (
                        <ChevronDown className='hidden w-6 h-6 text-gray-700 sm:block' />)  
                      }
                  </button>
                  {/*Dropdown Menu*/}
                  <div className={`
                    absolute right-0 mt-2 w-56 bg-white rounded-lg shadow-lg border border-gray-200 transform transform-all duration-200 ease-in-out
                    ${isOpen ? 'opacity-100 scale-100': 'opacity-0 scale-95 pointer-events-none'}
                    `}
                  >
                    <div className='p-2 border-b border-gray-200'>
                      <p className='text-sm text-gray-700'>Signed in as</p>
                      <p className='text-sm font-medium text-gray-900'>User@IdeationAxis.com</p>
                    </div>
                    <div className='py-1'>
                      {menuItems.map((item,index) => (
                        <a 
                          key={index} href={item.href}
                          className={`
                            flex items-center px-4 py-2 text-sm text-gray-700
                            hover:text-green-600 transition-colors
                            ${item.className || ''}
                          `}
                        >
                          <item.Icon className='w-5 h-5 mr-2 text-gray-600' />
                          {item.label}
                        </a>
                      ))}
                    </div>                    
                  </div>
                </div>
            </div>
          </div>
          </div>
        </div>
      </header>

      <main className='flex-1'>
        <div className='px-4 py-8 mx-auto max-w-7xl sm:px-6 lg:px-8'>
          {children}
        </div>        
      </main>
      
      <footer className='border-t border-gray-200 max-w'>
        <div className='mx-auto'>
          <div className='flex items-center justify-between w-full px-8 -mx-4 '>
            <div>
              <h2 className='text-lg font-bold text-gray-800'> Contacts</h2>
              <p className='text-gray-600'>Phone: 123-456-7890</p><br/>
              <p className='text-gray-600'>Email: 123@example.com</p>              
            </div>
            <div>
              <h2 className='text-lg font-bold text-gray-800'>Site Links</h2>
              <ul>
                <li><a href='homepage' className='text-gray-600 hover:text-green-600'>Home</a></li>
                <li><a href='Cartitems' className='text-gray-600 hover:text-green-600'>Cart</a></li>
                <li><a href='Orders' className='text-gray-600 hover:text-green-600'>Orders</a></li> 
              </ul>
            </div>
          </div>
          <div className='px-4 py-6 mx-auto max-w-7xl sm:px-6 lg:px-8'> 
            <p className='font-bold text-center text-gray-600'>
              © {new Date().getFullYear()} CropCircle | All Rights Reserved
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default CustomerLayout;