import { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Plus,
  Edit2,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Search,
  Filter,
  RefreshCw,
  AlertCircle,
  Check,
  X,
  Database,
  Smartphone,
  Apple,
} from 'lucide-react';
import type { SecurityRule, RuleType, RuleCreate, RuleUpdate, SeverityLevel } from '@/types/api';
import {
  getRules,
  createRule,
  updateRule,
  deleteRule,
  toggleRule,
  seedDefaultRules,
} from '@/lib/api';
import SeverityBadge from '@/components/SeverityBadge';

const RULE_TYPES: { value: RuleType; label: string; platform: 'android' | 'ios' }[] = [
  { value: 'root_detection', label: 'Root Detection', platform: 'android' },
  { value: 'ssl_pinning', label: 'SSL Pinning', platform: 'android' },
  { value: 'anti_tampering', label: 'Anti-Tampering', platform: 'android' },
  { value: 'ios_jailbreak', label: 'iOS Jailbreak', platform: 'ios' },
  { value: 'ios_ssl_pinning', label: 'iOS SSL Pinning', platform: 'ios' },
];

const SEVERITY_OPTIONS: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];
const DIFFICULTY_OPTIONS = ['easy', 'medium', 'hard'] as const;
const PLATFORM_OPTIONS = ['android', 'ios', 'both'] as const;

interface RuleFormData {
  name: string;
  type: RuleType;
  category: string;
  pattern: string;
  is_regex: boolean;
  case_sensitive: boolean;
  description: string;
  severity: SeverityLevel;
  bypass_difficulty: 'easy' | 'medium' | 'hard';
  platform: 'android' | 'ios' | 'both';
}

const defaultFormData: RuleFormData = {
  name: '',
  type: 'root_detection',
  category: '',
  pattern: '',
  is_regex: false,
  case_sensitive: true,
  description: '',
  severity: 'medium',
  bypass_difficulty: 'medium',
  platform: 'android',
};

export default function RulesPage() {
  const [rules, setRules] = useState<SecurityRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<RuleType | ''>('');
  const [filterPlatform, setFilterPlatform] = useState<'android' | 'ios' | 'both' | ''>('');
  const [showEnabledOnly, setShowEnabledOnly] = useState(false);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<SecurityRule | null>(null);
  const [formData, setFormData] = useState<RuleFormData>(defaultFormData);
  const [formLoading, setFormLoading] = useState(false);

  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const [summary, setSummary] = useState<Record<RuleType, number>>({} as Record<RuleType, number>);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getRules(
        filterType || undefined,
        filterPlatform || undefined,
        showEnabledOnly || undefined
      );
      setRules(response.rules);
      setSummary(response.by_type);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules');
    } finally {
      setLoading(false);
    }
  }, [filterType, filterPlatform, showEnabledOnly]);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const filteredRules = rules.filter((rule) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      rule.name.toLowerCase().includes(query) ||
      rule.pattern.toLowerCase().includes(query) ||
      rule.description.toLowerCase().includes(query) ||
      rule.category.toLowerCase().includes(query)
    );
  });

  const handleOpenModal = (rule?: SecurityRule) => {
    if (rule) {
      setEditingRule(rule);
      setFormData({
        name: rule.name,
        type: rule.type,
        category: rule.category,
        pattern: rule.pattern,
        is_regex: rule.is_regex,
        case_sensitive: rule.case_sensitive,
        description: rule.description,
        severity: rule.severity,
        bypass_difficulty: rule.bypass_difficulty,
        platform: rule.platform,
      });
    } else {
      setEditingRule(null);
      setFormData(defaultFormData);
    }
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setEditingRule(null);
    setFormData(defaultFormData);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormLoading(true);
    setError(null);

    try {
      if (editingRule) {
        const updateData: RuleUpdate = { ...formData };
        await updateRule(editingRule.id, updateData);
        setSuccessMessage('Rule updated successfully');
      } else {
        const createData: RuleCreate = { ...formData };
        await createRule(createData);
        setSuccessMessage('Rule created successfully');
      }
      handleCloseModal();
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save rule');
    } finally {
      setFormLoading(false);
    }
  };

  const handleToggle = async (id: number) => {
    try {
      const result = await toggleRule(id);
      setSuccessMessage(result.message);
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle rule');
    }
  };

  const handleDelete = async (id: number) => {
    try {
      const result = await deleteRule(id);
      setSuccessMessage(result.message);
      setDeleteConfirm(null);
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule');
    }
  };

  const handleSeedRules = async () => {
    setLoading(true);
    try {
      const result = await seedDefaultRules();
      setSuccessMessage(result.message);
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to seed rules');
      setLoading(false);
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'android':
        return <Smartphone className="h-4 w-4 text-green-600 dark:text-green-400" />;
      case 'ios':
        return <Apple className="h-4 w-4 text-gray-700 dark:text-gray-300" />;
      default:
        return (
          <div className="flex gap-0.5">
            <Smartphone className="h-3 w-3 text-green-600 dark:text-green-400" />
            <Apple className="h-3 w-3 text-gray-700 dark:text-gray-300" />
          </div>
        );
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy':
        return 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300';
      case 'hard':
        return 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Security Rules</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Manage detection patterns for security analysis
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleSeedRules}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <Database className="h-4 w-4" />
            Seed Defaults
          </button>
          <button
            onClick={() => handleOpenModal()}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700"
          >
            <Plus className="h-4 w-4" />
            Add Rule
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {RULE_TYPES.map(({ value, label, platform }) => (
          <div
            key={value}
            className={`p-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm cursor-pointer transition-all ${
              filterType === value ? 'ring-2 ring-blue-500' : 'hover:shadow-md'
            }`}
            onClick={() => setFilterType(filterType === value ? '' : value)}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-gray-500 dark:text-gray-400">{label}</span>
              {getPlatformIcon(platform)}
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{summary[value] || 0}</p>
          </div>
        ))}
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg">
          <AlertCircle className="h-5 w-5" />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {successMessage && (
        <div className="flex items-center gap-2 p-4 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded-lg">
          <Check className="h-5 w-5" />
          <span>{successMessage}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-4 p-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search rules..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as RuleType | '')}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            {RULE_TYPES.map(({ value, label }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>

          <select
            value={filterPlatform}
            onChange={(e) => setFilterPlatform(e.target.value as 'android' | 'ios' | 'both' | '')}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Platforms</option>
            <option value="android">Android</option>
            <option value="ios">iOS</option>
            <option value="both">Both</option>
          </select>

          <label className="flex items-center gap-2 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
            <input
              type="checkbox"
              checked={showEnabledOnly}
              onChange={(e) => setShowEnabledOnly(e.target.checked)}
              className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">Enabled only</span>
          </label>

          <button
            onClick={fetchRules}
            className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-blue-600 dark:text-blue-400 animate-spin" />
          </div>
        ) : filteredRules.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="h-12 w-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No rules found</p>
            <button onClick={handleSeedRules} className="mt-4 text-blue-600 dark:text-blue-400 hover:underline font-medium">
              Seed default rules
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  {['Status', 'Name', 'Type / Category', 'Pattern', 'Severity', 'Difficulty', 'Platform', 'Actions'].map((h, i) => (
                    <th key={h} className={`px-4 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider ${i === 7 ? 'text-right' : 'text-left'}`}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredRules.map((rule) => (
                  <tr key={rule.id} className={`hover:bg-gray-50 dark:hover:bg-gray-700/50 ${!rule.is_enabled ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <button onClick={() => handleToggle(rule.id)} className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200">
                        {rule.is_enabled ? <ToggleRight className="h-6 w-6 text-green-600 dark:text-green-400" /> : <ToggleLeft className="h-6 w-6 text-gray-400" />}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-900 dark:text-white">{rule.name}</span>
                        {rule.is_builtin && <span className="px-1.5 py-0.5 text-xs bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded">Built-in</span>}
                        {rule.is_regex && <span className="px-1.5 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/50 text-purple-700 dark:text-purple-300 rounded">Regex</span>}
                      </div>
                      {rule.description && <p className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">{rule.description}</p>}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="text-sm">
                        <span className="font-medium text-gray-900 dark:text-white">{RULE_TYPES.find((t) => t.value === rule.type)?.label || rule.type}</span>
                        <br /><span className="text-gray-500 dark:text-gray-400">{rule.category}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <code className="text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-gray-700 dark:text-gray-300 block max-w-xs truncate">{rule.pattern}</code>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap"><SeverityBadge severity={rule.severity} /></td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getDifficultyColor(rule.bypass_difficulty)}`}>{rule.bypass_difficulty}</span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-1">
                        {getPlatformIcon(rule.platform)}
                        <span className="text-sm text-gray-500 dark:text-gray-400 capitalize">{rule.platform}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button onClick={() => handleOpenModal(rule)} className="p-1 text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded">
                          <Edit2 className="h-4 w-4" />
                        </button>
                        {deleteConfirm === rule.id ? (
                          <div className="flex items-center gap-1">
                            <button onClick={() => handleDelete(rule.id)} className="p-1 text-white bg-red-600 hover:bg-red-700 rounded"><Check className="h-4 w-4" /></button>
                            <button onClick={() => setDeleteConfirm(null)} className="p-1 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><X className="h-4 w-4" /></button>
                          </div>
                        ) : (
                          <button onClick={() => setDeleteConfirm(rule.id)} className="p-1 text-gray-500 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded">
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {isModalOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center">
            <div className="fixed inset-0 bg-gray-500 dark:bg-gray-900 bg-opacity-75 dark:bg-opacity-80 transition-opacity" onClick={handleCloseModal} />
            <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full p-6 text-left">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{editingRule ? 'Edit Rule' : 'Create New Rule'}</h3>
                <button onClick={handleCloseModal} className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"><X className="h-5 w-5" /></button>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name *</label>
                    <input type="text" required value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" placeholder="Rule name" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type *</label>
                    <select required value={formData.type} onChange={(e) => setFormData({ ...formData, type: e.target.value as RuleType })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500">
                      {RULE_TYPES.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Category *</label>
                    <input type="text" required value={formData.category} onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" placeholder="e.g., native_checks" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Platform *</label>
                    <select required value={formData.platform} onChange={(e) => setFormData({ ...formData, platform: e.target.value as 'android' | 'ios' | 'both' })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500">
                      {PLATFORM_OPTIONS.map((p) => <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Pattern *</label>
                  <input type="text" required value={formData.pattern} onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 font-mono text-sm" placeholder="Search pattern or regex" />
                  <div className="flex gap-4 mt-2">
                    <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                      <input type="checkbox" checked={formData.is_regex} onChange={(e) => setFormData({ ...formData, is_regex: e.target.checked })} className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                      Regex pattern
                    </label>
                    <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                      <input type="checkbox" checked={formData.case_sensitive} onChange={(e) => setFormData({ ...formData, case_sensitive: e.target.checked })} className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                      Case sensitive
                    </label>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                  <textarea value={formData.description} onChange={(e) => setFormData({ ...formData, description: e.target.value })} rows={2}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" placeholder="What does this pattern detect?" />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Severity</label>
                    <select value={formData.severity} onChange={(e) => setFormData({ ...formData, severity: e.target.value as SeverityLevel })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500">
                      {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Bypass Difficulty</label>
                    <select value={formData.bypass_difficulty} onChange={(e) => setFormData({ ...formData, bypass_difficulty: e.target.value as 'easy' | 'medium' | 'hard' })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500">
                      {DIFFICULTY_OPTIONS.map((d) => <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>)}
                    </select>
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <button type="button" onClick={handleCloseModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-600">Cancel</button>
                  <button type="submit" disabled={formLoading} className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2">
                    {formLoading && <RefreshCw className="h-4 w-4 animate-spin" />}
                    {editingRule ? 'Update Rule' : 'Create Rule'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
