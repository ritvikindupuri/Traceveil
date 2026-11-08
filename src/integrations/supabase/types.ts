export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.18"
  }
  public: {
    Tables: {
      application_scans: {
        Row: {
          commit_sha: string
          created_at: string
          graph: Json
          id: string
          reports: Json
          status: string
          target: string
          user_id: string
        }
        Insert: {
          commit_sha: string
          created_at?: string
          graph: Json
          id?: string
          reports?: Json
          status?: string
          target: string
          user_id: string
        }
        Update: {
          commit_sha?: string
          created_at?: string
          graph?: Json
          id?: string
          reports?: Json
          status?: string
          target?: string
          user_id?: string
        }
        Relationships: []
      }
      audit_records: {
        Row: {
          connection_id: string | null
          created_at: string
          endpoint: string | null
          fingerprint: string
          id: string
          inventory: Json
          mode: string
          model: string
          reports: Json
          signals: Json
          source: string
          tools: Json
          user_id: string
          verdict: Json
        }
        Insert: {
          connection_id?: string | null
          created_at?: string
          endpoint?: string | null
          fingerprint: string
          id?: string
          inventory: Json
          mode: string
          model: string
          reports: Json
          signals: Json
          source: string
          tools?: Json
          user_id: string
          verdict: Json
        }
        Update: {
          connection_id?: string | null
          created_at?: string
          endpoint?: string | null
          fingerprint?: string
          id?: string
          inventory?: Json
          mode?: string
          model?: string
          reports?: Json
          signals?: Json
          source?: string
          tools?: Json
          user_id?: string
          verdict?: Json
        }
        Relationships: [
          {
            foreignKeyName: "audit_records_connection_id_fkey"
            columns: ["connection_id"]
            isOneToOne: false
            referencedRelation: "mcp_connections"
            referencedColumns: ["id"]
          },
        ]
      }
      audit_usage: {
        Row: {
          bucket: number
          count: number
          user_id: string
        }
        Insert: {
          bucket: number
          count?: number
          user_id: string
        }
        Update: {
          bucket?: number
          count?: number
          user_id?: string
        }
        Relationships: []
      }
      enforcement_events: {
        Row: {
          audit_id: string
          created_at: string
          decision: string
          id: string
          reason: string
          tool: string
          user_id: string
        }
        Insert: {
          audit_id: string
          created_at?: string
          decision: string
          id?: string
          reason: string
          tool: string
          user_id: string
        }
        Update: {
          audit_id?: string
          created_at?: string
          decision?: string
          id?: string
          reason?: string
          tool?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "enforcement_events_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audit_records"
            referencedColumns: ["id"]
          },
        ]
      }
      guardrail_policies: {
        Row: {
          policy: Json
          revision: string
          updated_at: string
          user_id: string
        }
        Insert: {
          policy: Json
          revision?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          policy?: Json
          revision?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      mcp_connections: {
        Row: {
          created_at: string
          enabled: boolean
          endpoint: string
          id: string
          name: string
          token_ciphertext: string | null
          user_id: string
        }
        Insert: {
          created_at?: string
          enabled?: boolean
          endpoint: string
          id?: string
          name: string
          token_ciphertext?: string | null
          user_id: string
        }
        Update: {
          created_at?: string
          enabled?: boolean
          endpoint?: string
          id?: string
          name?: string
          token_ciphertext?: string | null
          user_id?: string
        }
        Relationships: []
      }
      tenant_verification_plans: {
        Row: {
          approved_at: string
          commit_sha: string
          endpoint: string
          expires_at: string
          id: string
          id_pointer: string
          nonce: string
          rule: string
          scan_id: string
          suite_digest: string
          target: string
          user_id: string
        }
        Insert: {
          approved_at?: string
          commit_sha: string
          endpoint: string
          expires_at?: string
          id?: string
          id_pointer: string
          nonce?: string
          rule: string
          scan_id: string
          suite_digest: string
          target: string
          user_id: string
        }
        Update: {
          approved_at?: string
          commit_sha?: string
          endpoint?: string
          expires_at?: string
          id?: string
          id_pointer?: string
          nonce?: string
          rule?: string
          scan_id?: string
          suite_digest?: string
          target?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "tenant_verification_plans_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "application_scans"
            referencedColumns: ["id"]
          },
        ]
      }
      tenant_verification_runs: {
        Row: {
          artifact_digest: string
          created_at: string
          id: string
          outcome: string
          plan_id: string
          provenance: string
          result: Json
          user_id: string
        }
        Insert: {
          artifact_digest: string
          created_at?: string
          id?: string
          outcome: string
          plan_id: string
          provenance?: string
          result: Json
          user_id: string
        }
        Update: {
          artifact_digest?: string
          created_at?: string
          id?: string
          outcome?: string
          plan_id?: string
          provenance?: string
          result?: Json
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "tenant_verification_runs_plan_id_user_id_fkey"
            columns: ["plan_id", "user_id"]
            isOneToOne: false
            referencedRelation: "tenant_verification_plans"
            referencedColumns: ["id", "user_id"]
          },
        ]
      }
      tool_approvals: {
        Row: {
          audit_id: string
          created_at: string
          tools: string[]
          user_id: string
        }
        Insert: {
          audit_id: string
          created_at?: string
          tools: string[]
          user_id: string
        }
        Update: {
          audit_id?: string
          created_at?: string
          tools?: string[]
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "tool_approvals_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: true
            referencedRelation: "audit_records"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      consume_audit_quota: { Args: { p_user: string }; Returns: boolean }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
