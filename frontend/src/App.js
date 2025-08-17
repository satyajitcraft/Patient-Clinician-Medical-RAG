import React, { useState, useEffect, createContext, useContext } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route, Navigate, Link } from "react-router-dom";
import axios from "axios";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./components/ui/select";
import { Badge } from "./components/ui/badge";
import { Separator } from "./components/ui/separator";
import { Textarea } from "./components/ui/textarea";
import { Progress } from "./components/ui/progress";
import { AlertCircle, User, Stethoscope, FileText, Activity, Shield, Heart, Brain, Upload, Download, MessageCircle, BarChart3, FileUp, Smartphone, Clock, TrendingUp, Calendar, Settings } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      validateToken();
    } else {
      setLoading(false);
    }
  }, [token]);

  const validateToken = async () => {
    try {
      const response = await axios.get(`${API}/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUser(response.data);
    } catch (error) {
      console.error('Token validation failed:', error);
      logout();
    }
    setLoading(false);
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/login`, { email, password });
      const { access_token, user: userData } = response.data;
      
      setToken(access_token);
      setUser(userData);
      localStorage.setItem('token', access_token);
      
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Login failed' 
      };
    }
  };

  const register = async (userData) => {
    try {
      const response = await axios.post(`${API}/register`, userData);
      return { success: true, user: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Registration failed' 
      };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      loading,
      login,
      register,
      logout,
      isAuthenticated: !!user
    }}>
      {children}
    </AuthContext.Provider>
  );
};

// Auth Component
const AuthPage = () => {
  const { login, register } = useAuth();
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    full_name: '',
    role: '',
    license_number: '',
    specialty: '',
    date_of_birth: '',
    phone: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleRoleChange = (value) => {
    setFormData(prevData => ({
      ...prevData,
      role: value,
      license_number: value === 'clinician' ? prevData.license_number : '',
      specialty: value === 'clinician' ? prevData.specialty : '',
      date_of_birth: value === 'patient' ? prevData.date_of_birth : '',
      phone: value === 'patient' ? prevData.phone : ''
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        const result = await login(formData.email, formData.password);
        if (!result.success) {
          setError(result.error);
        }
      } else {
        const result = await register(formData);
        if (result.success) {
          setIsLogin(true);
          setError('');
          setFormData({ ...formData, password: '' });
        } else {
          setError(result.error);
        }
      }
    } catch (err) {
      setError('An unexpected error occurred');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-green-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-full mb-4">
            <Heart className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">HealthSync Platform</h1>
          <p className="text-gray-600 mt-2">Patient-Clinician Health Data Management</p>
        </div>

        <Card className="shadow-lg border-0 bg-white/80 backdrop-blur-sm">
          <CardHeader className="text-center pb-2">
            <CardTitle className="text-2xl">
              {isLogin ? 'Sign In' : 'Create Account'}
            </CardTitle>
            <CardDescription>
              {isLogin ? 'Access your health dashboard' : 'Join our healthcare platform'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 text-sm text-red-600 bg-red-50 p-3 rounded-lg">
                  <AlertCircle className="w-4 h-4" />
                  {error}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleInputChange}
                  placeholder="Enter your email"
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  value={formData.password}
                  onChange={handleInputChange}
                  placeholder="Enter your password"
                  required
                />
              </div>

              {!isLogin && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="full_name">Full Name</Label>
                    <Input
                      id="full_name"
                      name="full_name"
                      value={formData.full_name}
                      onChange={handleInputChange}
                      placeholder="Enter your full name"
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="role">Role</Label>
                    <Select value={formData.role} onValueChange={handleRoleChange}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select your role" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="patient">
                          <div className="flex items-center gap-2">
                            <User className="w-4 h-4" />
                            Patient
                          </div>
                        </SelectItem>
                        <SelectItem value="clinician">
                          <div className="flex items-center gap-2">
                            <Stethoscope className="w-4 h-4" />
                            Clinician
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {formData.role === 'clinician' && (
                    <>
                      <div className="space-y-2">
                        <Label htmlFor="license_number">License Number</Label>
                        <Input
                          id="license_number"
                          name="license_number"
                          value={formData.license_number}
                          onChange={handleInputChange}
                          placeholder="Enter your medical license number"
                          required
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="specialty">Specialty</Label>
                        <Input
                          id="specialty"
                          name="specialty"
                          value={formData.specialty}
                          onChange={handleInputChange}
                          placeholder="Enter your medical specialty"
                          required
                        />
                      </div>
                    </>
                  )}

                  {formData.role === 'patient' && (
                    <>
                      <div className="space-y-2">
                        <Label htmlFor="date_of_birth">Date of Birth</Label>
                        <Input
                          id="date_of_birth"
                          name="date_of_birth"
                          type="date"
                          value={formData.date_of_birth}
                          onChange={handleInputChange}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="phone">Phone Number</Label>
                        <Input
                          id="phone"
                          name="phone"
                          value={formData.phone}
                          onChange={handleInputChange}
                          placeholder="Enter your phone number"
                        />
                      </div>
                    </>
                  )}
                </>
              )}

              <Button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700"
                disabled={loading}
              >
                {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <button
                type="button"
                onClick={() => {
                  setIsLogin(!isLogin);
                  setError('');
                  setFormData({
                    email: '',
                    password: '',
                    full_name: '',
                    role: '',
                    license_number: '',
                    specialty: '',
                    date_of_birth: '',
                    phone: ''
                  });
                }}
                className="text-blue-600 hover:text-blue-700 text-sm font-medium"
              >
                {isLogin 
                  ? "Don't have an account? Sign up" 
                  : "Already have an account? Sign in"
                }
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user, logout, token } = useAuth();
  const [dashboardData, setDashboardData] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get(`${API}/dashboard`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setDashboardData(response.data);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    }
  };

  if (!dashboardData) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="text-gray-600 mt-4">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-10 h-10 bg-blue-600 rounded-lg">
                <Heart className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">HealthSync</h1>
                <p className="text-xs text-gray-500">Health Data Platform</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-900">{user.full_name}</p>
                  <div className="flex items-center gap-1">
                    <Badge variant={user.role === 'patient' ? 'default' : 'secondary'} className="text-xs">
                      {user.role === 'patient' ? (
                        <><User className="w-3 h-3 mr-1" /> Patient</>
                      ) : (
                        <><Stethoscope className="w-3 h-3 mr-1" /> Clinician</>
                      )}
                    </Badge>
                  </div>
                </div>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={logout}
                  className="text-gray-600 hover:text-gray-900"
                >
                  Sign Out
                </Button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-gray-900 mb-2">
            Welcome back, {user.full_name}
          </h2>
          <p className="text-gray-600">
            Manage your health data and get AI-powered insights
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card className="border-l-4 border-l-blue-500">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 mb-1">Documents</p>
                  <p className="text-2xl font-bold">{dashboardData.stats?.total_documents || 0}</p>
                </div>
                <FileText className="w-8 h-8 text-blue-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-green-500">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 mb-1">Analyses</p>
                  <p className="text-2xl font-bold">{dashboardData.stats?.total_analyses || 0}</p>
                </div>
                <Brain className="w-8 h-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-purple-500">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 mb-1">Wearables</p>
                  <p className="text-2xl font-bold">{dashboardData.stats?.wearable_connected ? '1' : '0'}</p>
                </div>
                <Smartphone className="w-8 h-8 text-purple-500" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="documents">Documents</TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
            <TabsTrigger value="wearables">Wearables</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <OverviewTab dashboardData={dashboardData} />
          </TabsContent>

          <TabsContent value="documents">
            <DocumentsTab token={token} />
          </TabsContent>

          <TabsContent value="analysis">
            <AnalysisTab token={token} />
          </TabsContent>

          <TabsContent value="wearables">
            <WearablesTab token={token} />
          </TabsContent>

          <TabsContent value="reports">
            <ReportsTab token={token} />
          </TabsContent>

          <TabsContent value="settings">
            <SettingsTab user={user} />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

// Overview Tab Component
const OverviewTab = ({ dashboardData }) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="w-5 h-5" />
            Recent Documents
          </CardTitle>
        </CardHeader>
        <CardContent>
          {dashboardData.recent_documents?.length > 0 ? (
            <div className="space-y-3">
              {dashboardData.recent_documents.map((doc, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <p className="font-medium text-sm">{doc.filename}</p>
                    <p className="text-xs text-gray-500">
                      {new Date(doc.uploaded_at).toLocaleDateString()}
                    </p>
                  </div>
                  <Badge variant="outline">PDF</Badge>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No documents uploaded yet</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5" />
            Recent Analyses
          </CardTitle>
        </CardHeader>
        <CardContent>
          {dashboardData.recent_analyses?.length > 0 ? (
            <div className="space-y-3">
              {dashboardData.recent_analyses.map((analysis, index) => (
                <div key={index} className="p-3 bg-gray-50 rounded-lg">
                  <p className="font-medium text-sm mb-1">{analysis.query}</p>
                  <p className="text-xs text-gray-500">
                    {new Date(analysis.created_at).toLocaleDateString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No analyses performed yet</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

// Documents Tab Component
const DocumentsTab = ({ token }) => {
  const [documents, setDocuments] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    fetchDocuments();
  }, []);

  const fetchDocuments = async () => {
    try {
      const response = await axios.get(`${API}/documents`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setDocuments(response.data.documents || []);
    } catch (error) {
      console.error('Error fetching documents:', error);
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    setUploading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('document_type', 'medical_record');

    try {
      await axios.post(`${API}/documents/upload`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      
      setSelectedFile(null);
      fetchDocuments();
      e.target.reset();
    } catch (error) {
      console.error('Upload failed:', error);
    }
    setUploading(false);
  };

  const handleDownload = async (documentId, filename) => {
    try {
      const response = await axios.get(`${API}/documents/${documentId}/download`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  return (
    <div className="space-y-6">
      {/* Upload Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="w-5 h-5" />
            Upload Medical Document
          </CardTitle>
          <CardDescription>
            Upload PDF medical documents for analysis and storage
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleFileUpload} className="space-y-4">
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
              <FileUp className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <div className="space-y-2">
                <Label htmlFor="file-upload" className="cursor-pointer">
                  <span className="text-blue-600 hover:text-blue-700 font-medium">
                    Choose a file
                  </span>
                  <span className="text-gray-500"> or drag and drop</span>
                </Label>
                <Input
                  id="file-upload"
                  type="file"
                  accept=".pdf"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  className="hidden"
                />
                <p className="text-xs text-gray-500">PDF files only, max 10MB</p>
              </div>
            </div>
            
            {selectedFile && (
              <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                <span className="text-sm font-medium">{selectedFile.name}</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedFile(null)}
                >
                  ×
                </Button>
              </div>
            )}
            
            <Button
              type="submit"
              disabled={!selectedFile || uploading}
              className="w-full"
            >
              {uploading ? 'Uploading...' : 'Upload Document'}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Documents List */}
      <Card>
        <CardHeader>
          <CardTitle>Your Documents</CardTitle>
        </CardHeader>
        <CardContent>
          {documents.length > 0 ? (
            <div className="space-y-3">
              {documents.map((doc) => (
                <div key={doc.document_id} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-blue-500" />
                    <div>
                      <p className="font-medium">{doc.filename}</p>
                      <div className="flex items-center gap-2 text-xs text-gray-500">
                        <span>{(doc.file_size / 1024).toFixed(1)} KB</span>
                        <span>•</span>
                        <span>{new Date(doc.uploaded_at).toLocaleDateString()}</span>
                        <span>•</span>
                        <Badge 
                          variant={doc.processing_status === 'completed' ? 'default' : 'secondary'}
                          className="text-xs"
                        >
                          {doc.processing_status}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDownload(doc.document_id, doc.filename)}
                  >
                    <Download className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No documents uploaded yet</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

// Analysis Tab Component
const AnalysisTab = ({ token }) => {
  const [query, setQuery] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentAnalyses, setRecentAnalyses] = useState([]);

  const handleAnalysis = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze`, {
        query: query,
        analysis_type: 'general'
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setAnalysisResult(response.data);
      setQuery('');
    } catch (error) {
      console.error('Analysis failed:', error);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      {/* Analysis Input */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MessageCircle className="w-5 h-5" />
            Ask Medical Question
          </CardTitle>
          <CardDescription>
            Ask questions about your medical documents and get AI-powered insights
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleAnalysis} className="space-y-4">
            <Textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="What would you like to know about your medical data? e.g., 'What are my recent vital signs?' or 'Summarize my latest lab results'"
              rows={4}
            />
            <Button
              type="submit"
              disabled={!query.trim() || loading}
              className="w-full"
            >
              {loading ? 'Analyzing...' : 'Analyze'}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Analysis Result */}
      {analysisResult && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="w-5 h-5" />
              Analysis Result
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="p-4 bg-blue-50 rounded-lg">
                <p className="font-medium text-blue-900 mb-2">Query:</p>
                <p className="text-blue-800">{analysisResult.query}</p>
              </div>
              
              <div className="p-4 bg-gray-50 rounded-lg">
                <p className="font-medium text-gray-900 mb-2">Response:</p>
                <p className="text-gray-800 whitespace-pre-wrap">{analysisResult.response}</p>
              </div>
              
              <div className="flex items-center justify-between text-sm text-gray-500">
                <div className="flex items-center gap-2">
                  <span>Confidence:</span>
                  <Progress value={analysisResult.confidence_score * 100} className="w-20 h-2" />
                  <span>{Math.round(analysisResult.confidence_score * 100)}%</span>
                </div>
                <span>{new Date(analysisResult.timestamp).toLocaleString()}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

// Wearables Tab Component
const WearablesTab = ({ token }) => {
  const [connectedDevices, setConnectedDevices] = useState([]);
  const [wearableData, setWearableData] = useState(null);

  const connectGoogleFit = async () => {
    try {
      const response = await axios.get(`${API}/wearable/google/auth`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      window.open(response.data.auth_url, '_blank');
    } catch (error) {
      console.error('Google Fit connection failed:', error);
    }
  };

  const connectFitbit = async () => {
    try {
      const response = await axios.get(`${API}/wearable/fitbit/auth`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      window.open(response.data.auth_url, '_blank');
    } catch (error) {
      console.error('Fitbit connection failed:', error);
    }
  };

  const fetchWearableData = async (dataType) => {
    try {
      const response = await axios.get(`${API}/wearable/data`, {
        params: {
          data_type: dataType,
          start_date: '2024-01-01',
          end_date: '2024-01-31'
        },
        headers: { Authorization: `Bearer ${token}` }
      });
      setWearableData(response.data);
    } catch (error) {
      console.error('Wearable data fetch failed:', error);
    }
  };

  return (
    <div className="space-y-6">
      {/* Connect Devices */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="w-5 h-5" />
            Connect Wearable Devices
          </CardTitle>
          <CardDescription>
            Connect your fitness devices to track health metrics
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 border rounded-lg text-center">
              <Activity className="w-12 h-12 text-green-500 mx-auto mb-3" />
              <h3 className="font-medium mb-2">Google Fit</h3>
              <Button onClick={connectGoogleFit} variant="outline" size="sm">
                Connect
              </Button>
            </div>
            
            <div className="p-4 border rounded-lg text-center">
              <Heart className="w-12 h-12 text-blue-500 mx-auto mb-3" />
              <h3 className="font-medium mb-2">Fitbit</h3>
              <Button onClick={connectFitbit} variant="outline" size="sm">
                Connect
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Data Visualization */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="cursor-pointer hover:shadow-md transition-shadow" onClick={() => fetchWearableData('steps')}>
          <CardContent className="p-6 text-center">
            <Activity className="w-8 h-8 text-blue-500 mx-auto mb-2" />
            <h3 className="font-medium">Steps</h3>
            <p className="text-2xl font-bold text-blue-600">8,500</p>
            <p className="text-xs text-gray-500">Daily average</p>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:shadow-md transition-shadow" onClick={() => fetchWearableData('heart_rate')}>
          <CardContent className="p-6 text-center">
            <Heart className="w-8 h-8 text-red-500 mx-auto mb-2" />
            <h3 className="font-medium">Heart Rate</h3>
            <p className="text-2xl font-bold text-red-600">72</p>
            <p className="text-xs text-gray-500">BPM average</p>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:shadow-md transition-shadow" onClick={() => fetchWearableData('sleep')}>
          <CardContent className="p-6 text-center">
            <Clock className="w-8 h-8 text-purple-500 mx-auto mb-2" />
            <h3 className="font-medium">Sleep</h3>
            <p className="text-2xl font-bold text-purple-600">7.2</p>
            <p className="text-xs text-gray-500">Hours average</p>
          </CardContent>
        </Card>
      </div>

      {/* Data Display */}
      {wearableData && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5" />
              {wearableData.data_type.charAt(0).toUpperCase() + wearableData.data_type.slice(1)} Data
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {wearableData.data.map((item, index) => (
                <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                  <span className="text-sm">{item.date}</span>
                  <span className="font-medium">{item.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

// Reports Tab Component
const ReportsTab = ({ token }) => {
  const [generating, setGenerating] = useState(false);

  const generateReport = async (reportType) => {
    setGenerating(true);
    try {
      const response = await axios.post(`${API}/reports/generate`, {}, {
        params: { report_type: reportType },
        headers: { Authorization: `Bearer ${token}` }
      });
      
      // Download the generated report
      const downloadResponse = await axios.get(`${API}/reports/${response.data.report_id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([downloadResponse.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `health_report_${reportType}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Report generation failed:', error);
    }
    setGenerating(false);
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="w-5 h-5" />
            Generate Health Reports
          </CardTitle>
          <CardDescription>
            Create comprehensive PDF reports of your health data
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-6 border rounded-lg text-center">
              <TrendingUp className="w-12 h-12 text-blue-500 mx-auto mb-4" />
              <h3 className="font-medium mb-2">Comprehensive Report</h3>
              <p className="text-sm text-gray-600 mb-4">
                Complete health overview with all metrics and trends
              </p>
              <Button 
                onClick={() => generateReport('comprehensive')} 
                disabled={generating}
                className="w-full"
              >
                {generating ? 'Generating...' : 'Generate Report'}
              </Button>
            </div>

            <div className="p-6 border rounded-lg text-center">
              <Calendar className="w-12 h-12 text-green-500 mx-auto mb-4" />
              <h3 className="font-medium mb-2">Monthly Summary</h3>
              <p className="text-sm text-gray-600 mb-4">
                Monthly health metrics and activity summary
              </p>
              <Button 
                onClick={() => generateReport('monthly')} 
                disabled={generating}
                variant="outline"
                className="w-full"
              >
                {generating ? 'Generating...' : 'Generate Report'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Settings Tab Component
const SettingsTab = ({ user }) => {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="w-5 h-5" />
            Account Settings
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label className="text-sm font-medium text-gray-700">Full Name</Label>
                <p className="text-gray-900">{user.full_name}</p>
              </div>
              <div>
                <Label className="text-sm font-medium text-gray-700">Email</Label>
                <p className="text-gray-900">{user.email}</p>
              </div>
              <div>
                <Label className="text-sm font-medium text-gray-700">Role</Label>
                <div className="flex items-center gap-2">
                  <Badge variant={user.role === 'patient' ? 'default' : 'secondary'}>
                    {user.role === 'patient' ? (
                      <><User className="w-3 h-3 mr-1" /> Patient</>
                    ) : (
                      <><Stethoscope className="w-3 h-3 mr-1" /> Clinician</>
                    )}
                  </Badge>
                </div>
              </div>
              {user.role === 'clinician' && (
                <>
                  <div>
                    <Label className="text-sm font-medium text-gray-700">License Number</Label>
                    <p className="text-gray-900">{user.license_number}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-gray-700">Specialty</Label>
                    <p className="text-gray-900">{user.specialty}</p>
                  </div>
                </>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Privacy & Security</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-green-600" />
                <div>
                  <p className="font-medium text-green-900">Data Encryption</p>
                  <p className="text-sm text-green-700">Your data is encrypted at rest and in transit</p>
                </div>
              </div>
              <Badge variant="default" className="bg-green-600">Active</Badge>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
              <div className="flex items-center gap-3">
                <Heart className="w-5 h-5 text-blue-600" />
                <div>
                  <p className="font-medium text-blue-900">HIPAA Compliant</p>
                  <p className="text-sm text-blue-700">Platform follows healthcare privacy standards</p>
                </div>
              </div>
              <Badge variant="default" className="bg-blue-600">Compliant</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="text-gray-600 mt-4">Loading...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/auth" replace />;
};

// Main App Component
function App() {
  return (
    <div className="App">
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/auth" element={<AuthPage />} />
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/" 
              element={<Navigate to="/dashboard" replace />} 
            />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </div>
  );
}

export default App;