import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Upload, Search, FileText, Lock, Bug } from 'lucide-react';
import FileUpload from '@/components/FileUpload';

export default function HomePage() {
  const navigate = useNavigate();
  const [showUpload, setShowUpload] = useState(false);

  const handleUploadSuccess = (reportId: number) => {
    navigate(`/reports/${reportId}`);
  };

  const features = [
    {
      icon: Search,
      title: 'Static Analysis (SAST)',
      description: 'Deep code analysis to find SQL injection, hardcoded secrets, and more',
    },
    {
      icon: FileText,
      title: 'Manifest Analysis',
      description: 'Analyze permissions, components, and security configurations',
    },
    {
      icon: Lock,
      title: 'Certificate Analysis',
      description: 'Verify signing certificates and detect debug signatures',
    },
    {
      icon: Bug,
      title: 'Vulnerability Detection',
      description: 'Identify OWASP Mobile Top 10 vulnerabilities',
    },
  ];

  return (
    <div className="space-y-12">
      {/* Hero Section */}
      <div className="text-center">
        <div className="flex justify-center mb-6">
          <Shield className="h-20 w-20 text-blue-600 dark:text-blue-400" />
        </div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">
          Mobile Analyzer
        </h1>
        <p className="text-xl text-gray-600 dark:text-gray-300 max-w-2xl mx-auto mb-8">
          Comprehensive Android APK & iOS IPA security analysis tool. 
          Upload a mobile app file to discover vulnerabilities, misconfigurations, 
          and security risks.
        </p>
        
        {!showUpload ? (
          <button
            onClick={() => setShowUpload(true)}
            className="inline-flex items-center px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Upload className="h-5 w-5 mr-2" />
            Upload APK/IPA for Analysis
          </button>
        ) : (
          <div className="max-w-xl mx-auto">
            <FileUpload onUploadSuccess={handleUploadSuccess} />
            <button
              onClick={() => setShowUpload(false)}
              className="mt-4 text-sm text-gray-500 hover:text-gray-700"
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {/* Features Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        {features.map(({ icon: Icon, title, description }) => (
          <div
            key={title}
            className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md transition-shadow"
          >
            <Icon className="h-10 w-10 text-blue-600 dark:text-blue-400 mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">{title}</h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm">{description}</p>
          </div>
        ))}
      </div>

      {/* Stats or Info Section */}
      <div className="bg-blue-50 dark:bg-gray-800 rounded-lg p-8 border border-blue-100 dark:border-gray-700">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 text-center">
          Security Checks Performed
        </h2>
        <div className="grid md:grid-cols-3 gap-6 text-center">
          <div>
            <p className="text-4xl font-bold text-blue-600 dark:text-blue-400">20+</p>
            <p className="text-gray-600 dark:text-gray-400">Security Patterns</p>
          </div>
          <div>
            <p className="text-4xl font-bold text-blue-600 dark:text-blue-400">OWASP</p>
            <p className="text-gray-600 dark:text-gray-400">Mobile Top 10</p>
          </div>
          <div>
            <p className="text-4xl font-bold text-blue-600 dark:text-blue-400">CWE</p>
            <p className="text-gray-600 dark:text-gray-400">Mapped Findings</p>
          </div>
        </div>
      </div>

      {/* Quick Links */}
      <div className="flex justify-center space-x-4">
        <button
          onClick={() => navigate('/reports')}
          className="px-4 py-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
        >
          View All Reports →
        </button>
      </div>
    </div>
  );
}
