const { createClient } = require('@supabase/supabase-js');

exports.handler = async function(event, context) {
    // Get authorization header
    const authHeader = event.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return {
            statusCode: 401,
            body: JSON.stringify({ error: 'Unauthorized' })
        };
    }

    const token = authHeader.split('Bearer ')[1];

    try {
        // Initialize Supabase
        const supabaseUrl = process.env.SUPABASE_URL;
        const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
        
        if (!supabaseUrl || !supabaseKey) {
            return {
                statusCode: 500,
                body: JSON.stringify({ error: 'Server configuration error' })
            };
        }

        const supabase = createClient(supabaseUrl, supabaseKey);

        // Verify the token and get user
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        
        if (authError || !user) {
            return {
                statusCode: 401,
                body: JSON.stringify({ error: 'Invalid token' })
            };
        }

        // Check user role
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('role')
            .eq('id', user.id)
            .single();

        if (userError || !userData) {
            return {
                statusCode: 403,
                body: JSON.stringify({ error: 'Access denied' })
            };
        }

        // Handle different endpoints
        const path = event.path.split('/').pop();
        
        switch (path) {
            case 'stats':
                return handleStats(supabase, user.id, event.httpMethod);
            
            case 'users':
                if (userData.role !== 'admin') {
                    return {
                        statusCode: 403,
                        body: JSON.stringify({ error: 'Admin access required' })
                    };
                }
                return handleUsers(supabase, event.httpMethod);
            
            case 'content':
                return handleContent(supabase, user.id, event.httpMethod, JSON.parse(event.body || '{}'));
            
            default:
                return {
                    statusCode: 404,
                    body: JSON.stringify({ error: 'Endpoint not found' })
                };
        }

    } catch (error) {
        console.error('API error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};

async function handleStats(supabase, userId, method) {
    if (method !== 'GET') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        // Get user stats
        const { data: userStats, error: userError } = await supabase
            .from('users')
            .select('meditation_streak, total_meditations, journal_entries')
            .eq('id', userId)
            .single();

        if (userError) throw userError;

        // Get recent journal entries
        const { data: journalEntries, error: journalError } = await supabase
            .from('journal_entries')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(5);

        if (journalError) throw journalError;

        return {
            statusCode: 200,
            body: JSON.stringify({
                userStats,
                recentJournals: journalEntries
            })
        };

    } catch (error) {
        console.error('Stats error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Failed to fetch stats' })
        };
    }
}

async function handleUsers(supabase, method) {
    if (method !== 'GET') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(50);

        if (error) throw error;

        return {
            statusCode: 200,
            body: JSON.stringify({ users })
        };

    } catch (error) {
        console.error('Users error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Failed to fetch users' })
        };
    }
}

async function handleContent(supabase, userId, method, data) {
    switch (method) {
        case 'GET':
            try {
                const { data: content, error } = await supabase
                    .from('content')
                    .select('*')
                    .eq('published', true)
                    .order('created_at', { ascending: false });

                if (error) throw error;

                return {
                    statusCode: 200,
                    body: JSON.stringify({ content })
                };

            } catch (error) {
                console.error('Get content error:', error);
                return {
                    statusCode: 500,
                    body: JSON.stringify({ error: 'Failed to fetch content' })
                };
            }

        case 'POST':
            try {
                if (!data.title || !data.content) {
                    return {
                        statusCode: 400,
                        body: JSON.stringify({ error: 'Missing required fields' })
                    };
                }

                const { data: newContent, error } = await supabase
                    .from('content')
                    .insert([
                        {
                            user_id: userId,
                            title: data.title,
                            content: data.content,
                            type: data.type || 'article',
                            published: data.published || false,
                            created_at: new Date().toISOString()
                        }
                    ])
                    .select()
                    .single();

                if (error) throw error;

                return {
                    statusCode: 201,
                    body: JSON.stringify({ content: newContent })
                };

            } catch (error) {
                console.error('Create content error:', error);
                return {
                    statusCode: 500,
                    body: JSON.stringify({ error: 'Failed to create content' })
                };
            }

        default:
            return {
                statusCode: 405,
                body: JSON.stringify({ error: 'Method not allowed' })
            };
    }
}