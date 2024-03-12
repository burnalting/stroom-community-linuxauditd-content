<xsl:stylesheet xmlns="event-logging:3" xpath-default-namespace="event-logging:3" xmlns:stroom="stroom" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0">

  <!-- 
  
  Linux Auditd NPE/Non-NPE Translation:
  
  CHANGE HISTORY 
  v1.0.0 - 20170402 Burn Alting 
  Created from scratch 
  
  The purpose of this translation is to NOT translate those Linux auditd events where all user related elements are Non Person Entities
  such as root, unset, bin, etc. These users are identified by the {RunAs,User}/Type elements containing the text 'NPE'.
  
  The setting of the NPE user type is done in the emitUserId template in the LINUX-AUDITD-AUSHAPE-V3-EVENTS translation
  
  -->

  <!-- Match all events -->
  <xsl:template match="Events">
   <xsl:element name="Events">
      <xsl:attribute name="xsi:schemaLocation">
        <xsl:value-of select="@xsi:schemaLocation" />
      </xsl:attribute>
      <xsl:attribute name="Version">
        <xsl:value-of select="@Version" />
      </xsl:attribute>

      <!--
      To work out if we have only NPE users, we count the {RunAs,User} elements and then count the {RunAs,User} elements that have a Type sub-element of 'NPE'
      If the count is the same then it is all NPE users, if it's different then we have at least one non NPE user.
      Thus if we are after Non NPE user based events then we select those that match
      (count(.//User) ne count(.//User/Type[text()='NPE'])) or (count(.//RunAs) ne count(.//RunAs/Type[text()='NPE']))
      
      -->
      <xsl:apply-templates select="Event[(count(.//User) ne count(.//User/Type[text()='NPE'])) or (count(.//RunAs) ne count(.//RunAs/Type[text()='NPE']))]" mode="npe" />
    </xsl:element>
  </xsl:template>

  <!-- Ensure at least one non-npe user -->
  <xsl:template match="Event" mode="npe">
    <xsl:copy-of select="." copy-namespaces="no"/>
  </xsl:template>
</xsl:stylesheet>
